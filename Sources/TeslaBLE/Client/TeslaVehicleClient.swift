import CryptoKit
import Foundation

/// Primary entry point for TeslaBLE.
///
/// A `TeslaVehicleClient` owns a BLE session with a single Tesla vehicle
/// identified by VIN. The typical lifecycle is: create the client, call
/// ``connect(mode:timeout:)``, issue ``send(_:timeout:)`` commands and
/// ``fetch(_:timeout:)`` / ``query(_:timeout:)`` requests, then
/// ``disconnect()``.
///
/// The type is an `actor`, so all calls are serialized and safe to invoke
/// from any task. Use one client per VIN; discard and recreate to target a
/// different vehicle.
public actor TeslaVehicleClient {
    // MARK: - Stored

    /// VIN of the vehicle this client is bound to.
    public let vin: String
    private let keyStore: any TeslaKeyStore
    private let logger: (any TeslaBLELogger)?

    private var transport: BLETransport?
    private var dispatcher: Dispatcher?

    private var _state: ConnectionState = .disconnected
    private let stream: AsyncStream<ConnectionState>
    private let streamContinuation: AsyncStream<ConnectionState>.Continuation

    // MARK: - Init

    /// Creates a client bound to a specific vehicle VIN.
    ///
    /// The client does not touch Bluetooth until ``connect(mode:timeout:)``
    /// is called. A matching private key for `vin` must already exist in
    /// `keyStore` by the time `connect` runs in `.normal` mode.
    ///
    /// - Parameters:
    ///   - vin: 17-character Tesla VIN identifying the target vehicle.
    ///   - keyStore: Storage for the P-256 client private key. TeslaBLE never
    ///     writes to the store; callers provision keys externally.
    ///   - logger: Optional diagnostic sink. Pass `nil` to silence internal
    ///     logging entirely.
    public init(
        vin: String,
        keyStore: any TeslaKeyStore,
        logger: (any TeslaBLELogger)? = nil,
    ) {
        self.vin = vin
        self.keyStore = keyStore
        self.logger = logger
        let (stream, continuation) = AsyncStream.makeStream(of: ConnectionState.self)
        self.stream = stream
        streamContinuation = continuation
    }

    // MARK: - Public API

    /// How ``TeslaVehicleClient/connect(mode:timeout:)`` should bring the
    /// session up.
    ///
    /// Use ``normal`` for essentially all real usage. ``pairing`` is a
    /// one-off bootstrap mode needed only the very first time a client's
    /// key is being added to a vehicle it has never seen before.
    public enum ConnectMode: Sendable {
        /// Scan, BLE connect, then run the signed session handshake on both
        /// the VCSEC and Infotainment domains. The standard connect path.
        case normal
        /// Scan and BLE connect only; skip the session handshake.
        ///
        /// Used exclusively for first-time pairing: the vehicle has no
        /// record of the client's public key, so a signed handshake cannot
        /// succeed. After connecting in this mode, the caller must issue
        /// `Command.security(.addKey(...))` and have a user tap a
        /// previously-enrolled owner key on the center console to
        /// authorize. Afterwards, disconnect and reconnect with ``normal``.
        case pairing
    }

    /// The client's current connection state. Equivalent to the most recent
    /// value yielded on ``stateStream``.
    public var state: ConnectionState {
        _state
    }

    /// Stream of ``ConnectionState`` transitions.
    ///
    /// The stream yields the state after each transition and never finishes
    /// for the lifetime of the client. It is safe to observe from any task
    /// and is intentionally `nonisolated` so observers do not need to hop
    /// onto the actor.
    public nonisolated var stateStream: AsyncStream<ConnectionState> {
        stream
    }

    /// Brings the BLE session up and, unless pairing, runs the per-domain
    /// session handshake.
    ///
    /// In ``ConnectMode/normal`` mode the state machine walks
    /// ``ConnectionState/scanning`` → ``ConnectionState/connecting`` →
    /// ``ConnectionState/handshaking`` → ``ConnectionState/connected``. In
    /// ``ConnectMode/pairing`` mode the handshake step is skipped.
    ///
    /// Calling `connect` while already connected or mid-connect is a no-op.
    ///
    /// - Parameters:
    ///   - mode: Whether to run the signed handshake after the BLE connect.
    ///   - timeout: Upper bound for the whole connect flow including scan,
    ///     BLE connect, and per-domain handshakes.
    /// - Throws: ``TeslaBLEError`` if scan, BLE connect, or handshake fails.
    public func connect(
        mode: ConnectMode = .normal,
        timeout: Duration = .seconds(30),
    ) async throws {
        guard _state == .disconnected else {
            logger?.log(.warning, category: "client", "connect() called while in state \(_state); ignoring")
            return
        }

        let privateKey = try loadPrivateKey()

        // BLE connect.
        let transport = BLETransport(logger: logger)
        self.transport = transport
        transport.onStateChange = { [weak self] bleState in
            Task { [weak self] in
                await self?.handleTransportStateChange(bleState)
            }
        }
        updateState(.scanning)
        do {
            try await transport.connect(vin: vin, timeout: Self.seconds(timeout))
        } catch {
            logger?.log(.error, category: "client", "BLE connect failed: \(error)")
            await tearDown()
            throw Self.mapTransportError(error)
        }

        // Start dispatcher.
        let dispatcher = Dispatcher(transport: transport, logger: logger)
        self.dispatcher = dispatcher
        do {
            try await dispatcher.start()
        } catch {
            await tearDown()
            throw TeslaBLEError.handshakeFailed(underlying: String(describing: error))
        }

        guard mode == .normal else {
            // Pairing path — skip handshake.
            updateState(.connected)
            return
        }

        updateState(.handshaking)
        do {
            try await negotiateBothDomains(
                dispatcher: dispatcher,
                localPrivateKey: privateKey,
                timeout: timeout,
            )
        } catch {
            await tearDown()
            throw error
        }

        updateState(.connected)
    }

    /// Tears down the BLE session and returns to
    /// ``ConnectionState/disconnected``. Safe to call in any state.
    public func disconnect() async {
        await tearDown()
    }

    /// Sends a typed command to the vehicle and waits for its acknowledgement.
    ///
    /// Most commands travel the signed path and require an established
    /// session for their domain; ``TeslaBLEError/notConnected`` is thrown
    /// otherwise. The one exception is ``Command/Security/addKey(publicKey:role:formFactor:)``,
    /// which uses the unsigned VCSEC pairing path and must be issued after
    /// connecting with ``ConnectMode/pairing``. That pairing request returns
    /// once the request is transmitted over BLE; the user still needs to tap
    /// an existing owner key on the center console, then reconnect in normal
    /// mode to verify the newly-added key is active.
    ///
    /// - Parameters:
    ///   - command: The command to dispatch.
    ///   - timeout: Maximum time to wait for the vehicle's response.
    /// - Throws: ``TeslaBLEError/notConnected``,
    ///   ``TeslaBLEError/commandTimeout``, or
    ///   ``TeslaBLEError/commandRejected(code:reason:)`` if the vehicle
    ///   rejects the request.
    public func send(_ command: Command, timeout: Duration = .seconds(10)) async throws {
        guard let dispatcher else { throw TeslaBLEError.notConnected }
        let (domain, body) = try CommandEncoder.encode(command)

        // Unsigned pairing path: addKey is issued before any session exists.
        // Match Tesla's reference behavior and return once the request has
        // been transmitted; the vehicle may complete authorization later.
        if case .security(.addKey) = command {
            do {
                try await dispatcher.sendUnsignedNoReply(
                    body,
                    domain: domain,
                )
            } catch {
                throw Self.mapAddKeyError(error)
            }
            return
        }

        // Normal signed path (requires an installed VehicleSession for the domain).
        let responseBytes: Data
        do {
            responseBytes = try await dispatcher.send(body, domain: domain, timeout: timeout)
        } catch {
            throw Self.mapDispatcherError(error)
        }
        try decodeCommandResult(responseBytes: responseBytes, domain: domain)
    }

    private func decodeCommandResult(
        responseBytes: Data,
        domain: UniversalMessage_Domain,
    ) throws {
        let result: ResponseDecoder.CommandResult
        switch domain {
        case .vehicleSecurity:
            result = try ResponseDecoder.decodeVCSEC(responseBytes)
        case .infotainment:
            result = try ResponseDecoder.decodeInfotainment(responseBytes)
        default:
            throw TeslaBLEError.handshakeFailed(underlying: "unknown domain \(domain)")
        }
        switch result {
        case .ok, .okWithPayload:
            return
        case let .vehicleError(code, reason):
            throw TeslaBLEError.commandRejected(code: code, reason: reason)
        }
    }

    /// Fetches a structured snapshot of vehicle state from the Infotainment
    /// domain.
    ///
    /// - Parameters:
    ///   - query: Which categories of state to request. See ``StateQuery``
    ///     for the bandwidth/latency tradeoffs between ``StateQuery/all``
    ///     and ``StateQuery/driveOnly``.
    ///   - timeout: Maximum time to wait for the response.
    /// - Returns: Mapped ``TeslaVehicleSnapshot`` built from the vehicle's
    ///   protobuf response.
    /// - Throws: ``TeslaBLEError`` if the request or decode fails.
    public func fetch(
        _ query: StateQuery = .all,
        timeout: Duration = .seconds(10),
    ) async throws -> TeslaVehicleSnapshot {
        let raw = try await fetchRaw(query: query, timeout: timeout)
        return VehicleSnapshotMapper.map(raw)
    }

    /// Low-latency fast path that fetches only the drive state subset.
    ///
    /// Prefer this over ``fetch(_:timeout:)`` when polling for gear, speed,
    /// or heading while driving; the smaller response finishes in a few
    /// hundred milliseconds instead of the full-snapshot latency.
    ///
    /// - Parameter timeout: Maximum time to wait for the response.
    public func fetchDrive(timeout: Duration = .seconds(3)) async throws -> DriveState {
        let raw = try await fetchRaw(query: .driveOnly, timeout: timeout)
        return VehicleSnapshotMapper.mapDrive(raw)
    }

    /// Runs a structured-response vehicle query.
    ///
    /// Unlike ``send(_:timeout:)``, which returns `Void`, queries return
    /// typed payloads — each ``VehicleQuery`` case has its own response
    /// shape (VCSEC whitelist, body controller status, nearby
    /// superchargers, and so on).
    ///
    /// - Parameters:
    ///   - query: The query to dispatch.
    ///   - timeout: Maximum time to wait for the response.
    /// - Returns: A ``VehicleQueryResult`` whose case matches `query`.
    /// - Throws: ``TeslaBLEError`` on transport, timeout, or decode failure.
    public func query(
        _ query: VehicleQuery,
        timeout: Duration = .seconds(10),
    ) async throws -> VehicleQueryResult {
        guard let dispatcher else { throw TeslaBLEError.notConnected }
        let (domain, body): (UniversalMessage_Domain, Data)
        do {
            (domain, body) = try VehicleQueryEncoder.encode(query)
        } catch {
            throw TeslaBLEError.fetchFailed(underlying: String(describing: error))
        }
        let responseBytes: Data
        do {
            responseBytes = try await dispatcher.send(body, domain: domain, timeout: timeout)
        } catch {
            throw Self.mapDispatcherError(error)
        }
        do {
            return try VehicleQueryDecoder.decode(query, from: responseBytes)
        } catch {
            throw TeslaBLEError.fetchFailed(underlying: String(describing: error))
        }
    }

    // MARK: - Private

    private func fetchRaw(query: StateQuery, timeout: Duration) async throws -> CarServer_VehicleData {
        guard let dispatcher else { throw TeslaBLEError.notConnected }
        let body: Data
        do {
            body = try StateQueryEncoder.encode(query)
        } catch {
            throw TeslaBLEError.fetchFailed(underlying: String(describing: error))
        }
        let responseBytes: Data
        do {
            responseBytes = try await dispatcher.send(body, domain: .infotainment, timeout: timeout)
        } catch {
            throw Self.mapDispatcherError(error)
        }
        do {
            let response = try CarServer_Response(serializedBytes: responseBytes)
            guard case let .vehicleData(data)? = response.responseMsg else {
                throw TeslaBLEError.fetchFailed(underlying: "response has no vehicleData payload")
            }
            return data
        } catch let error as TeslaBLEError {
            throw error
        } catch {
            throw TeslaBLEError.fetchFailed(underlying: String(describing: error))
        }
    }

    private func loadPrivateKey() throws -> P256.KeyAgreement.PrivateKey {
        do {
            if let key = try keyStore.loadPrivateKey(forVIN: vin) {
                return key
            }
        } catch let error as TeslaBLEError {
            throw error
        } catch {
            throw TeslaBLEError.handshakeFailed(underlying: "key load failed: \(error)")
        }
        throw TeslaBLEError.handshakeFailed(underlying: "no private key for VIN \(vin); call registerKey() first")
    }

    private func negotiateBothDomains(
        dispatcher: Dispatcher,
        localPrivateKey: P256.KeyAgreement.PrivateKey,
        timeout: Duration,
    ) async throws {
        let verifierName = Data(vin.utf8)
        let localPublicKey = localPrivateKey.publicKey.x963Representation

        for domain in [UniversalMessage_Domain.vehicleSecurity, .infotainment] {
            let negotiated: (sessionInfo: Signatures_SessionInfo, sessionKey: SessionKey)
            do {
                negotiated = try await dispatcher.negotiate(
                    domain: domain,
                    localPrivateKey: localPrivateKey,
                    verifierName: verifierName,
                    timeout: timeout,
                )
            } catch {
                throw TeslaBLEError.handshakeFailed(
                    underlying: "domain \(domain) negotiate: \(error)",
                )
            }

            let session = VehicleSession(
                domain: domain,
                verifierName: verifierName,
                localPublicKey: localPublicKey,
                sessionKey: negotiated.sessionKey,
                epoch: negotiated.sessionInfo.epoch,
                initialCounter: negotiated.sessionInfo.counter,
                clockTime: negotiated.sessionInfo.clockTime,
            )
            await dispatcher.installSession(session, forDomain: domain)
        }
    }

    private func handleTransportStateChange(_ bleState: BLETransport.ConnectionState) {
        switch bleState {
        case .disconnected:
            if _state != .disconnected { updateState(.disconnected) }
        case .scanning:
            if _state == .disconnected { updateState(.scanning) }
        case .connecting:
            updateState(.connecting)
        case .connected:
            // Client elevates to .handshaking or .connected itself.
            break
        }
    }

    private func updateState(_ newState: ConnectionState) {
        _state = newState
        streamContinuation.yield(newState)
        logger?.log(.debug, category: "client", "state → \(newState)")
    }

    private func tearDown() async {
        if let dispatcher { await dispatcher.stop() }
        dispatcher = nil
        transport?.disconnect()
        transport = nil
        if _state != .disconnected {
            updateState(.disconnected)
        }
    }

    private static func seconds(_ duration: Duration) -> TimeInterval {
        let components = duration.components
        return TimeInterval(components.seconds)
            + TimeInterval(components.attoseconds) / 1e18
    }

    private static func mapTransportError(_ error: Error) -> TeslaBLEError {
        if let bleError = error as? BLEError {
            switch bleError {
            case .bluetoothUnavailable: return .bluetoothUnavailable
            case .notConnected: return .notConnected
            case .connectionFailed: return .connectionFailed(underlying: "connect failed")
            case .disconnected: return .connectionFailed(underlying: "peer disconnected")
            case .serviceNotFound: return .serviceNotFound
            case .characteristicsNotFound: return .characteristicsNotFound
            case .messageTooLarge: return .messageTooLarge
            case .timeout: return .scanTimeout
            }
        }
        return .connectionFailed(underlying: (error as NSError).localizedDescription)
    }

    private static func mapDispatcherError(_ error: Error) -> TeslaBLEError {
        if let d = error as? Dispatcher.Error {
            switch d {
            case .notStarted, .notConnected: return .notConnected
            case .alreadyStarted: return .notConnected
            case .noSessionForDomain: return .notConnected
            case .timeout: return .commandTimeout
            case .shutdown: return .notConnected
            case let .encodingFailed(s), let .decodingFailed(s), let .unexpectedResponse(s):
                return .fetchFailed(underlying: s)
            }
        }
        if let t = error as? TeslaBLEError {
            return t
        }
        return .fetchFailed(underlying: (error as NSError).localizedDescription)
    }

    private static func mapAddKeyError(_ error: Error) -> TeslaBLEError {
        if let bleError = error as? BLEError {
            return mapTransportError(bleError)
        }
        if let dispatcherError = error as? Dispatcher.Error {
            switch dispatcherError {
            case .notStarted, .notConnected, .alreadyStarted, .noSessionForDomain, .shutdown:
                return .notConnected
            case .timeout:
                return .addKeyFailed(underlying: "timed out sending addKey request")
            case let .encodingFailed(message),
                 let .decodingFailed(message),
                 let .unexpectedResponse(message):
                return .addKeyFailed(underlying: message)
            }
        }
        if let teslaError = error as? TeslaBLEError {
            return teslaError
        }
        return .addKeyFailed(underlying: (error as NSError).localizedDescription)
    }
}
