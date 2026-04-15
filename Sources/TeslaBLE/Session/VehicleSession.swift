import Foundation

/// Long-lived per-domain session state. One instance per BLE domain (VCSEC,
/// INFOTAINMENT), held for as long as the BLE connection is alive, and the
/// single owner of all mutable crypto state. `OutboundSigner` and
/// `InboundVerifier` are deliberately stateless so that this actor is the
/// only place counter/epoch updates can happen — which is what lets the
/// replay window and counter monotonicity be reasoned about locally.
///
/// Concurrency: `actor` so multiple in-flight commands cannot race on the
/// counter (two concurrent signs must produce two distinct counter values).
actor VehicleSession {
    enum Error: Swift.Error, Equatable {
        case counterRollover
        case signFailed(String)
        case verifyFailed(String)
    }

    /// The BLE domain this session belongs to (VCSEC or INFOTAINMENT).
    let domain: UniversalMessage_Domain
    /// Personalization bytes — VIN for infotainment, VCSEC id for vehicle
    /// security — bound into every AAD so a signature for one vehicle
    /// cannot be replayed against another.
    let verifierName: Data
    /// Local public key, copied verbatim into `signerIdentity` on every
    /// outbound message so the vehicle can identify the signing party.
    let localPublicKey: Data
    /// 16-byte AES-GCM key derived from the ECDH handshake. Immutable for
    /// the lifetime of the session; a new session is required to rotate it.
    let sessionKey: SessionKey

    /// Vehicle-advertised 16-byte epoch. Rotates when the vehicle requests
    /// a resync; refreshed via `resync(fromSessionInfo:)`.
    private var epoch: Data
    /// Monotonically-increasing outbound counter. Incremented before each
    /// `sign` call and rolled back if sealing fails.
    private var counter: UInt32

    /// Wall-clock moment the vehicle's current epoch (according to its
    /// monotonic clock) would have started, computed as
    /// `handshakeDate - clockTime seconds`. Used to compute outbound
    /// `expiresAt` in the vehicle's epoch timebase — the vehicle rejects
    /// commands whose `expiresAt` is less than `timeSince(sessionStart)`,
    /// so this MUST be set from `SessionInfo.clockTime` received at
    /// handshake (see `internal/authentication/signer.go` `NewSigner` +
    /// `epochStartTime`). Refreshed on `resync(fromSessionInfo:)`.
    private var sessionStart: Date

    init(
        domain: UniversalMessage_Domain,
        verifierName: Data,
        localPublicKey: Data,
        sessionKey: SessionKey,
        epoch: Data,
        initialCounter: UInt32 = 0,
        clockTime: UInt32 = 0,
        handshakeDate: Date = Date(),
    ) {
        self.domain = domain
        self.verifierName = verifierName
        self.localPublicKey = localPublicKey
        self.sessionKey = sessionKey
        self.epoch = epoch
        counter = initialCounter
        sessionStart = handshakeDate.addingTimeInterval(-TimeInterval(clockTime))
    }

    /// Outbound sign: increments counter, seals plaintext into message.
    ///
    /// `expiresIn` is a relative TTL. The absolute `expiresAt` written into
    /// the message is `floor(secondsSinceSessionStart + expiresIn)` — i.e.
    /// a timestamp in the vehicle's epoch timebase, matching
    /// `signer.go` `encryptWithCounter`:
    /// `uint32(time.Now().Add(expiresIn).Sub(s.timeZero) / time.Second)`.
    func sign(
        plaintext: Data,
        into message: inout UniversalMessage_RoutableMessage,
        expiresIn: TimeInterval,
    ) throws {
        if counter == UInt32.max {
            throw Error.counterRollover
        }
        counter &+= 1
        let expiresAt = Self.computeExpiresAt(sessionStart: sessionStart, expiresIn: expiresIn)
        do {
            try OutboundSigner.signGCM(
                plaintext: plaintext,
                message: &message,
                sessionKey: sessionKey,
                localPublicKey: localPublicKey,
                verifierName: verifierName,
                epoch: epoch,
                counter: counter,
                expiresAt: expiresAt,
            )
        } catch {
            // Rollback counter so the next attempt reuses the same value.
            counter &-= 1
            throw Error.signFailed(String(describing: error))
        }
    }

    /// Inbound verify: opens the AES-GCM response envelope and returns the
    /// plaintext. No session-level replay window is maintained here because
    /// the vehicle only guarantees counter monotonicity *per request ID*
    /// (see `internal/authentication/verifier.go Encrypt` doc and
    /// `internal/dispatcher/receiver.go antireplay`, which is a fresh
    /// per-receiver window in Go). Duplicate responses are dropped earlier
    /// by `Dispatcher.RequestTable`, which removes the token on the first
    /// completion, so duplicates never reach `verify`.
    func verify(
        response: UniversalMessage_RoutableMessage,
        requestID: Data,
    ) throws -> Data {
        do {
            let result = try InboundVerifier.openGCMResponse(
                message: response,
                sessionKey: sessionKey,
                verifierName: verifierName,
                requestID: requestID,
            )
            return result.plaintext
        } catch {
            throw Error.verifyFailed(String(describing: error))
        }
    }

    /// Resync this session to a freshly-received (and HMAC-verified)
    /// `SessionInfo`. Updates epoch, counter, and sessionStart atomically
    /// and resets the inbound replay window. Called from the dispatcher
    /// inbound loop when the vehicle proactively attaches updated session
    /// info to a response (see `internal/authentication/signer.go`
    /// `UpdateSessionInfo`).
    ///
    /// The caller is responsible for HMAC-verifying `info` before calling
    /// this method — this function does not re-verify.
    func resync(fromSessionInfo info: Signatures_SessionInfo, handshakeDate: Date = Date()) {
        epoch = info.epoch
        counter = info.counter
        sessionStart = handshakeDate.addingTimeInterval(-TimeInterval(info.clockTime))
    }

    // MARK: - Helpers

    /// `floor((now - sessionStart) + expiresIn)` clamped to `UInt32`.
    private static func computeExpiresAt(sessionStart: Date, expiresIn: TimeInterval) -> UInt32 {
        let delta = Date().timeIntervalSince(sessionStart) + expiresIn
        guard delta.isFinite, delta > 0 else { return 0 }
        let clamped = min(delta, TimeInterval(UInt32.max))
        return UInt32(clamped.rounded(.down))
    }

// Test-only accessors.
#if DEBUG
    var currentCounter: UInt32 {
        counter
    }

    var currentEpoch: Data {
        epoch
    }

    var currentSessionStart: Date {
        sessionStart
    }
#endif
}
