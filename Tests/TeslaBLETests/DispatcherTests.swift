import CryptoKit
import Foundation
@testable import TeslaBLE
import XCTest

final class DispatcherTests: XCTestCase {
    // MARK: - RequestTable

    /// Wraps RequestTable (a value type) in a class so Swift 6 strict-concurrency
    /// lets us capture the same table across multiple async-let closures.
    private final class TableBox: @unchecked Sendable {
        var table = RequestTable()
    }

    func testRequestTableRegisterComplete() async throws {
        let box = TableBox()
        let uuid = Data([0xDE, 0xAD, 0xBE, 0xEF])

        async let received: UniversalMessage_RoutableMessage = withCheckedThrowingContinuation { cont in
            do {
                try box.table.register(token: uuid, continuation: cont)
            } catch {
                cont.resume(throwing: error)
            }
        }

        // Give the async let a chance to register before we complete.
        try await Task.sleep(nanoseconds: 10_000_000)

        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = uuid
        let found = box.table.complete(token: uuid, with: response)
        XCTAssertTrue(found)

        let got = try await received
        XCTAssertEqual(got.requestUuid, uuid)
        XCTAssertTrue(box.table.isEmpty)
    }

    func testRequestTableFailPropagatesError() async throws {
        enum Canary: Swift.Error, Equatable { case boom }

        let box = TableBox()
        let uuid = Data([0x01, 0x02])

        async let result: UniversalMessage_RoutableMessage = withCheckedThrowingContinuation { cont in
            do {
                try box.table.register(token: uuid, continuation: cont)
            } catch {
                cont.resume(throwing: error)
            }
        }

        try await Task.sleep(nanoseconds: 10_000_000)

        let found = box.table.fail(token: uuid, error: Canary.boom)
        XCTAssertTrue(found)

        do {
            _ = try await result
            XCTFail("expected error")
        } catch Canary.boom {
            // ok
        }
        XCTAssertTrue(box.table.isEmpty)
    }

    func testRequestTableCancelAllWakesEveryone() async throws {
        enum Canary: Swift.Error, Equatable { case shutdown }

        // Use an actor to serialize all access to the RequestTable, avoiding
        // data races when multiple tasks register continuations concurrently.
        actor TableActor {
            var table = RequestTable()
            func register(uuid: Data, continuation: RequestTable.Continuation) throws {
                try table.register(token: uuid, continuation: continuation)
            }

            func count() -> Int {
                table.count
            }

            func cancelAll(error: Swift.Error) {
                table.cancelAll(error: error)
            }

            func isEmpty() -> Bool {
                table.isEmpty
            }
        }

        let actor = TableActor()
        let uuidA = Data([0xA1])
        let uuidB = Data([0xB2])

        // Spawn two tasks, each of which registers a continuation and then
        // suspends. The tasks run concurrently but table access is serialized
        // by the actor.
        let taskA = Task { () -> UniversalMessage_RoutableMessage in
            return try await withCheckedThrowingContinuation { cont in
                Task { try? await actor.register(uuid: uuidA, continuation: cont) }
            }
        }
        let taskB = Task { () -> UniversalMessage_RoutableMessage in
            return try await withCheckedThrowingContinuation { cont in
                Task { try? await actor.register(uuid: uuidB, continuation: cont) }
            }
        }

        // Wait for both registrations to land.
        try await Task.sleep(nanoseconds: 20_000_000)
        let countBeforeCancel = await actor.count()
        XCTAssertEqual(countBeforeCancel, 2)

        await actor.cancelAll(error: Canary.shutdown)
        let emptyAfterCancel = await actor.isEmpty()
        XCTAssertTrue(emptyAfterCancel)

        var failures = 0
        do { _ = try await taskA.value } catch Canary.shutdown { failures += 1 }
        do { _ = try await taskB.value } catch Canary.shutdown { failures += 1 }
        XCTAssertEqual(failures, 2)
    }

    // MARK: - Dispatcher helpers

    private func makeSessionKey() -> SessionKey {
        SessionKey(rawBytes: Data(repeating: 0x42, count: 16))
    }

    private func makeSession(domain: UniversalMessage_Domain, initialCounter: UInt32 = 0) -> VehicleSession {
        VehicleSession(
            domain: domain,
            verifierName: Data("test_verifier".utf8),
            localPublicKey: Data(repeating: 0x04, count: 65),
            sessionKey: makeSessionKey(),
            epoch: Data(repeating: 0xAB, count: 16),
            initialCounter: initialCounter,
        )
    }

    /// Seal a canned response plaintext with the supplied session parameters
    /// and return the serialized `UniversalMessage_RoutableMessage` bytes
    /// ready to hand back through `FakeTransport.enqueueInbound`.
    private func makeResponseBytes(
        respondingTo request: UniversalMessage_RoutableMessage,
        plaintext: Data,
        counter: UInt32,
        sessionKey: SessionKey,
        verifierName: Data,
        domain: UniversalMessage_Domain,
    ) throws -> Data {
        let requestID = try XCTUnwrap(InboundVerifier.requestID(forSignedRequest: request))

        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        var from = UniversalMessage_Destination()
        from.domain = domain
        response.fromDestination = from
        // Vehicle echoes the client's fromDestination.routingAddress into the
        // response's toDestination.routingAddress. Dispatcher matches VCSEC
        // responses on this field (not on requestUuid).
        if case let .routingAddress(addr)? = request.fromDestination.subDestination {
            var to = UniversalMessage_Destination()
            to.routingAddress = addr
            response.toDestination = to
        }

        let aad = try SessionMetadata.buildResponseAAD(
            message: response,
            verifierName: verifierName,
            requestID: requestID,
            counter: counter,
        )
        let fixedNonce = Data([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
        let sealed = try MessageAuthenticator.sealFixed(
            plaintext: plaintext,
            associatedData: aad,
            nonce: fixedNonce,
            sessionKey: sessionKey,
        )

        var gcm = Signatures_AES_GCM_Response_Signature_Data()
        gcm.nonce = fixedNonce
        gcm.counter = counter
        gcm.tag = sealed.tag
        var sigData = Signatures_SignatureData()
        sigData.sigType = .aesGcmResponseData(gcm)
        response.subSigData = .signatureData(sigData)
        response.payload = .protobufMessageAsBytes(sealed.ciphertext)

        return try response.serializedData()
    }

    // MARK: - Dispatcher happy path

    func testDispatcherSendAndReceivesResponse() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .vehicleSecurity)
        await dispatcher.installSession(session, forDomain: .vehicleSecurity)

        // Kick off the send on a background task so we can interleave the
        // response injection below.
        let sendTask = Task { () throws -> Data in
            try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity, timeout: .seconds(2))
        }

        // Wait for the outbound bytes to appear.
        var outbound: [Data] = []
        for _ in 0 ..< 50 {
            outbound = await transport.sentMessages
            if !outbound.isEmpty { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTAssertEqual(outbound.count, 1, "dispatcher should have written exactly one outbound message")

        let outboundRequest = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        XCTAssertEqual(outboundRequest.toDestination.domain, .vehicleSecurity)

        // Seal a canned response using the same session parameters.
        let responseBytes = try makeResponseBytes(
            respondingTo: outboundRequest,
            plaintext: Data("OK".utf8),
            counter: 1,
            sessionKey: makeSessionKey(),
            verifierName: Data("test_verifier".utf8),
            domain: .vehicleSecurity,
        )
        await transport.enqueueInbound(responseBytes)

        let responsePlaintext = try await sendTask.value
        XCTAssertEqual(responsePlaintext, Data("OK".utf8))

        await dispatcher.stop()
    }

    func testDispatcherSendUnsignedNoReplyReturnsAfterTransmit() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        let start = ContinuousClock.now
        try await dispatcher.sendUnsignedNoReply(Data([0xAA, 0xBB, 0xCC]), domain: .vehicleSecurity)
        let elapsed = ContinuousClock.now - start

        XCTAssertLessThan(elapsed, .seconds(1), "one-way addKey bootstrap should not wait for a response")

        let outbound = await transport.sentMessages
        XCTAssertEqual(outbound.count, 1)

        let message = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        XCTAssertEqual(message.toDestination.domain, .vehicleSecurity)
        XCTAssertFalse(message.uuid.isEmpty)
        guard case let .protobufMessageAsBytes(payload)? = message.payload else {
            XCTFail("expected protobuf payload")
            return
        }
        XCTAssertEqual(payload, Data([0xAA, 0xBB, 0xCC]))

        await dispatcher.stop()
    }

    // MARK: - Dispatcher timeout

    func testDispatcherSendTimesOut() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .vehicleSecurity)
        await dispatcher.installSession(session, forDomain: .vehicleSecurity)

        let start = ContinuousClock.now
        do {
            _ = try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity, timeout: .milliseconds(200))
            XCTFail("expected timeout")
        } catch Dispatcher.Error.timeout {
            // ok
        }
        let elapsed = ContinuousClock.now - start
        XCTAssertLessThan(elapsed, .seconds(1), "timeout should fire close to the deadline")

        await dispatcher.stop()
    }

    // MARK: - Dispatcher error paths

    func testDispatcherRejectsSendWithoutSession() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        do {
            _ = try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity)
            XCTFail("expected noSessionForDomain")
        } catch let Dispatcher.Error.noSessionForDomain(d) {
            XCTAssertEqual(d, .vehicleSecurity)
        }

        await dispatcher.stop()
    }

    func testDispatcherDropsInboundWithUnknownRequestUUID() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .vehicleSecurity)
        await dispatcher.installSession(session, forDomain: .vehicleSecurity)

        // Enqueue a bogus inbound whose requestUuid does not match anything.
        var bogus = UniversalMessage_RoutableMessage()
        bogus.requestUuid = Data([0xFF, 0xFF])
        let bogusBytes = try bogus.serializedData()
        await transport.enqueueInbound(bogusBytes)

        // Give the inbound loop a moment to process+drop the unknown message.
        try await Task.sleep(nanoseconds: 50_000_000)

        // Now send a legit command. Dispatcher should work normally despite
        // the earlier dropped inbound.
        let sendTask = Task { () throws -> Data in
            try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity, timeout: .seconds(2))
        }

        var outbound: [Data] = []
        for _ in 0 ..< 50 {
            outbound = await transport.sentMessages
            if !outbound.isEmpty { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTAssertEqual(outbound.count, 1)

        let outboundRequest = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        let responseBytes = try makeResponseBytes(
            respondingTo: outboundRequest,
            plaintext: Data("OK".utf8),
            counter: 1,
            sessionKey: makeSessionKey(),
            verifierName: Data("test_verifier".utf8),
            domain: .vehicleSecurity,
        )
        await transport.enqueueInbound(responseBytes)

        let result = try await sendTask.value
        XCTAssertEqual(result, Data("OK".utf8))

        await dispatcher.stop()
    }

    // MARK: - Dispatcher stop() wakes in-flight sends

    func testDispatcherStopFailsInFlightSends() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .vehicleSecurity)
        await dispatcher.installSession(session, forDomain: .vehicleSecurity)

        let sendTask = Task { () throws -> Data in
            try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity, timeout: .seconds(30))
        }

        // Wait for the outbound write to confirm the send is registered and suspended.
        for _ in 0 ..< 50 {
            let sent = await transport.sentMessages
            if !sent.isEmpty { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }

        // Stop the dispatcher — should wake the suspended send with .shutdown.
        await dispatcher.stop()

        do {
            _ = try await sendTask.value
            XCTFail("expected shutdown error")
        } catch Dispatcher.Error.shutdown {
            // ok
        }
    }

    // MARK: - Dispatcher handshake roundtrip

    func testDispatcherNegotiateRoundtrip() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        // Both sides get real P-256 keypairs.
        let clientKey = P256.KeyAgreement.PrivateKey()
        let vehicleKey = P256.KeyAgreement.PrivateKey()
        let vehiclePublicBytes = vehicleKey.publicKey.x963Representation

        // The shared secret is what the vehicle side "knows" for signing the
        // response tag. We pre-compute it the same way Dispatcher will.
        let sharedSecret = try P256ECDH.sharedSecret(
            localScalar: vehicleKey.rawRepresentation,
            peerPublicUncompressed: clientKey.publicKey.x963Representation,
        )
        let sessionKey = SessionKey.derive(fromSharedSecret: sharedSecret)

        let verifierName = Data("test_verifier".utf8)

        // Kick off the negotiation.
        let negotiateTask = Task { () throws -> (Signatures_SessionInfo, SessionKey) in
            try await dispatcher.negotiate(
                domain: .vehicleSecurity,
                localPrivateKey: clientKey,
                verifierName: verifierName,
                timeout: .seconds(2),
            )
        }

        // Wait for the SessionInfoRequest write.
        var outbound: [Data] = []
        for _ in 0 ..< 50 {
            outbound = await transport.sentMessages
            if !outbound.isEmpty { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTAssertEqual(outbound.count, 1)
        let outboundRequest = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        guard case let .sessionInfoRequest(req)? = outboundRequest.payload else {
            XCTFail("expected SessionInfoRequest payload"); return
        }
        XCTAssertTrue(req.challenge.isEmpty, "SessionInfoRequest.challenge is unused — vehicle keys the HMAC on RoutableMessage.uuid")
        XCTAssertEqual(outboundRequest.uuid.count, 16, "RoutableMessage.uuid is the real HMAC challenge")
        XCTAssertTrue(outboundRequest.hasFromDestination, "SessionInfoRequest must set fromDestination")
        guard case let .routingAddress(addr)? = outboundRequest.fromDestination.subDestination else {
            XCTFail("fromDestination must carry a routingAddress"); return
        }
        XCTAssertEqual(addr.count, 16, "routing address is 16 bytes")
        XCTAssertNotEqual(addr, Data(count: 16), "routing address must be random, not all zeros")

        // Construct a SessionInfo response with the vehicle's real public key.
        var info = Signatures_SessionInfo()
        info.counter = 7
        info.epoch = Data(repeating: 0xAB, count: 16)
        info.clockTime = 99
        info.publicKey = vehiclePublicBytes
        let encoded = try info.serializedData()

        // Sign the response with the shared session key.
        let tag = try SessionNegotiator.computeSessionInfoTag(
            sessionKey: sessionKey,
            verifierName: verifierName,
            challenge: outboundRequest.uuid,
            encodedInfo: encoded,
        )

        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = outboundRequest.uuid
        stampRouting(on: &response, respondingTo: outboundRequest, domain: .vehicleSecurity)
        response.payload = .sessionInfo(encoded)
        var sig = Signatures_SignatureData()
        var hmac = Signatures_HMAC_Signature_Data()
        hmac.tag = tag
        sig.sigType = .sessionInfoTag(hmac)
        response.subSigData = .signatureData(sig)
        let responseBytes = try response.serializedData()
        await transport.enqueueInbound(responseBytes)

        let (decodedInfo, derivedKey) = try await negotiateTask.value
        XCTAssertEqual(decodedInfo.counter, 7)
        XCTAssertEqual(decodedInfo.clockTime, 99)
        XCTAssertEqual(derivedKey, sessionKey, "dispatcher should derive the same session key")

        await dispatcher.stop()
    }

    // MARK: - fromDestination.routingAddress

    /// Vehicles fold `fromDestination.routingAddress` into the session-info
    /// HMAC metadata. Without it they reply with an unsigned SessionInfo
    /// broadcast that cannot complete a handshake (observed bug on real cars).
    func testSessionNegotiatorBuildRequestSetsRoutingAddress() {
        let publicKey = Data(repeating: 0x04, count: 65)
        let routingAddress = Data((0 ..< 16).map { UInt8($0 + 1) })

        let message = SessionNegotiator.buildRequest(
            domain: .vehicleSecurity,
            publicKey: publicKey,
            uuid: Data([0x01, 0x02]),
            fromRoutingAddress: routingAddress,
        )

        XCTAssertTrue(message.hasFromDestination)
        guard case let .routingAddress(addr)? = message.fromDestination.subDestination else {
            XCTFail("fromDestination must carry a routingAddress"); return
        }
        XCTAssertEqual(addr, routingAddress)
        XCTAssertEqual(message.toDestination.domain, .vehicleSecurity)
    }

    func testDispatcherSendUnsignedNoReplySetsRoutingAddress() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        try await dispatcher.sendUnsignedNoReply(
            Data("pair".utf8),
            domain: .vehicleSecurity,
        )

        // The request is fire-and-forget, but the outbound bytes should already
        // be recorded by FakeTransport.
        let outbound = await transport.sentMessages
        XCTAssertEqual(outbound.count, 1)
        let msg = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        XCTAssertTrue(msg.hasFromDestination)
        guard case let .routingAddress(addr)? = msg.fromDestination.subDestination else {
            XCTFail("fromDestination must carry a routingAddress"); return
        }
        XCTAssertEqual(addr.count, 16)
        XCTAssertNotEqual(addr, Data(count: 16))

        await dispatcher.stop()
    }

    // MARK: - sendUnsigned (reply variant)

    func testDispatcherSendUnsignedRoundtrip() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        let sendTask = Task { () throws -> Data in
            try await dispatcher.sendUnsigned(
                Data("vcsecInformationRequest".utf8),
                domain: .vehicleSecurity,
                timeout: .seconds(2),
            )
        }

        // Wait for the outbound request and build a matching unsigned response.
        var outbound: [Data] = []
        for _ in 0 ..< 50 {
            outbound = await transport.sentMessages
            if !outbound.isEmpty { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTAssertEqual(outbound.count, 1)
        let request = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        XCTAssertTrue(request.hasFromDestination)

        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        stampRouting(on: &response, respondingTo: request, domain: .vehicleSecurity)
        response.payload = .protobufMessageAsBytes(Data("fromVCSEC".utf8))
        try await transport.enqueueInbound(response.serializedData())

        let payload = try await sendTask.value
        XCTAssertEqual(payload, Data("fromVCSEC".utf8))

        await dispatcher.stop()
    }

    func testDispatcherSendUnsignedRejectsResponseWithoutPayload() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        let sendTask = Task { () throws -> Data in
            try await dispatcher.sendUnsigned(
                Data("req".utf8),
                domain: .vehicleSecurity,
                timeout: .seconds(2),
            )
        }

        var outbound: [Data] = []
        for _ in 0 ..< 50 {
            outbound = await transport.sentMessages
            if !outbound.isEmpty { break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTAssertEqual(outbound.count, 1)
        let request = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])

        // Response without a protobufMessageAsBytes payload.
        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        stampRouting(on: &response, respondingTo: request, domain: .vehicleSecurity)
        // No payload set.
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await sendTask.value
            XCTFail("expected decodingFailed")
        } catch let Dispatcher.Error.decodingFailed(reason) {
            XCTAssertTrue(reason.contains("unsigned response"), "got: \(reason)")
        }

        await dispatcher.stop()
    }

    // MARK: - Negotiate error paths

    func testDispatcherNegotiateRejectsResponseMissingSessionInfo() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let clientKey = P256.KeyAgreement.PrivateKey()

        let task = Task { () throws -> (Signatures_SessionInfo, SessionKey) in
            try await dispatcher.negotiate(
                domain: .vehicleSecurity,
                localPrivateKey: clientKey,
                verifierName: Data("v".utf8),
                timeout: .seconds(2),
            )
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let request = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        stampRouting(on: &response, respondingTo: request, domain: .vehicleSecurity)
        // No payload → triggers missing sessionInfo branch.
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await task.value
            XCTFail("expected unexpectedResponse")
        } catch let Dispatcher.Error.unexpectedResponse(reason) {
            XCTAssertTrue(reason.contains("missing sessionInfo payload"), "got: \(reason)")
        }
        await dispatcher.stop()
    }

    func testDispatcherNegotiateRejectsResponseMissingSignatureData() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let clientKey = P256.KeyAgreement.PrivateKey()

        let task = Task { () throws -> (Signatures_SessionInfo, SessionKey) in
            try await dispatcher.negotiate(
                domain: .vehicleSecurity,
                localPrivateKey: clientKey,
                verifierName: Data("v".utf8),
                timeout: .seconds(2),
            )
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let request = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        var info = Signatures_SessionInfo()
        info.publicKey = Data(repeating: 0x04, count: 65)
        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        stampRouting(on: &response, respondingTo: request, domain: .vehicleSecurity)
        response.payload = try .sessionInfo(info.serializedData())
        // No subSigData → triggers missing signature data branch.
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await task.value
            XCTFail("expected unexpectedResponse")
        } catch let Dispatcher.Error.unexpectedResponse(reason) {
            XCTAssertTrue(reason.contains("missing signature data"), "got: \(reason)")
        }
        await dispatcher.stop()
    }

    func testDispatcherNegotiateRejectsWrongSignatureType() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let clientKey = P256.KeyAgreement.PrivateKey()

        let task = Task { () throws -> (Signatures_SessionInfo, SessionKey) in
            try await dispatcher.negotiate(
                domain: .vehicleSecurity,
                localPrivateKey: clientKey,
                verifierName: Data("v".utf8),
                timeout: .seconds(2),
            )
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let request = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        var info = Signatures_SessionInfo()
        info.publicKey = Data(repeating: 0x04, count: 65)
        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        stampRouting(on: &response, respondingTo: request, domain: .vehicleSecurity)
        response.payload = try .sessionInfo(info.serializedData())

        // Signature present but wrong type (hmacPersonalizedData instead of sessionInfoTag).
        var hmac = Signatures_HMAC_Personalized_Signature_Data()
        hmac.tag = Data(repeating: 0xAA, count: 16)
        var sig = Signatures_SignatureData()
        sig.sigType = .hmacPersonalizedData(hmac)
        response.subSigData = .signatureData(sig)
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await task.value
            XCTFail("expected unexpectedResponse")
        } catch let Dispatcher.Error.unexpectedResponse(reason) {
            XCTAssertTrue(reason.contains("wrong signature type"), "got: \(reason)")
        }
        await dispatcher.stop()
    }

    func testDispatcherNegotiateRejectsHMACTagMismatch() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let clientKey = P256.KeyAgreement.PrivateKey()
        let vehicleKey = P256.KeyAgreement.PrivateKey()

        let task = Task { () throws -> (Signatures_SessionInfo, SessionKey) in
            try await dispatcher.negotiate(
                domain: .vehicleSecurity,
                localPrivateKey: clientKey,
                verifierName: Data("v".utf8),
                timeout: .seconds(2),
            )
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let request = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        // Well-formed SessionInfo + a deliberately-wrong HMAC tag.
        var info = Signatures_SessionInfo()
        info.publicKey = vehicleKey.publicKey.x963Representation
        info.epoch = Data(repeating: 0xAB, count: 16)
        info.counter = 1

        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        stampRouting(on: &response, respondingTo: request, domain: .vehicleSecurity)
        response.payload = try .sessionInfo(info.serializedData())

        var tag = Signatures_HMAC_Signature_Data()
        tag.tag = Data(repeating: 0xFF, count: 16) // wrong
        var sig = Signatures_SignatureData()
        sig.sigType = .sessionInfoTag(tag)
        response.subSigData = .signatureData(sig)
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await task.value
            XCTFail("expected unexpectedResponse")
        } catch let Dispatcher.Error.unexpectedResponse(reason) {
            XCTAssertTrue(reason.contains("HMAC tag mismatch"), "got: \(reason)")
        }
        await dispatcher.stop()
    }

    func testDispatcherNegotiateRejectsMalformedVehiclePublicKey() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let clientKey = P256.KeyAgreement.PrivateKey()

        let task = Task { () throws -> (Signatures_SessionInfo, SessionKey) in
            try await dispatcher.negotiate(
                domain: .vehicleSecurity,
                localPrivateKey: clientKey,
                verifierName: Data("v".utf8),
                timeout: .seconds(2),
            )
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let request = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        // SessionInfo with a bogus vehicle public key (wrong length).
        var info = Signatures_SessionInfo()
        info.publicKey = Data(repeating: 0x00, count: 3) // not a P-256 point

        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = request.uuid
        stampRouting(on: &response, respondingTo: request, domain: .vehicleSecurity)
        response.payload = try .sessionInfo(info.serializedData())

        var tag = Signatures_HMAC_Signature_Data()
        tag.tag = Data(repeating: 0xAA, count: 16)
        var sig = Signatures_SignatureData()
        sig.sigType = .sessionInfoTag(tag)
        response.subSigData = .signatureData(sig)
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await task.value
            XCTFail("expected decodingFailed")
        } catch let Dispatcher.Error.decodingFailed(reason) {
            XCTAssertTrue(reason.contains("ECDH"), "got: \(reason)")
        }
        await dispatcher.stop()
    }

    // MARK: - Session routing

    func testDispatcherRequireSessionRejectsUnsupportedDomain() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        do {
            _ = try await dispatcher.send(Data("x".utf8), domain: .broadcast)
            XCTFail("expected noSessionForDomain")
        } catch let Dispatcher.Error.noSessionForDomain(d) {
            XCTAssertEqual(d, .broadcast)
        }

        await dispatcher.stop()
    }

    func testDispatcherInstallsInfotainmentSessionIndependently() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let infotainment = makeSession(domain: .infotainment)
        await dispatcher.installSession(infotainment, forDomain: .infotainment)

        // VCSEC still has no session.
        do {
            _ = try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity)
            XCTFail("expected noSessionForDomain(vcsec)")
        } catch Dispatcher.Error.noSessionForDomain(.vehicleSecurity) {
            // ok
        }

        await dispatcher.stop()
    }

    // MARK: - Helpers (coverage tests)

    /// Fill in the routing fields the real dispatcher now requires on inbound
    /// messages: `fromDestination.domain` tells the inbound loop which
    /// routing scheme to use; `toDestination.routingAddress` echoes the
    /// client's request address so VCSEC responses match by address.
    private func stampRouting(
        on response: inout UniversalMessage_RoutableMessage,
        respondingTo request: UniversalMessage_RoutableMessage,
        domain: UniversalMessage_Domain,
    ) {
        var from = UniversalMessage_Destination()
        from.domain = domain
        response.fromDestination = from
        if case let .routingAddress(addr)? = request.fromDestination.subDestination {
            var to = UniversalMessage_Destination()
            to.routingAddress = addr
            response.toDestination = to
        }
    }

    private func waitForFirstOutbound(_ transport: FakeTransport) async throws -> Data {
        for _ in 0 ..< 100 {
            let sent = await transport.sentMessages
            if let first = sent.first { return first }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("no outbound message")
        throw Dispatcher.Error.timeout
    }

    // MARK: - Protocol-layer fault surfacing

    /// Vehicles report protocol-layer errors as a bare `signedMessageStatus`
    /// with no `signatureData`. The dispatcher must surface the fault name
    /// instead of falling through to the verifier's opaque
    /// `missingSignatureData`. Mirrors `protocol.GetError` in Go.
    func testDispatcherSurfacesSignedMessageFaultBeforeVerify() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .infotainment)
        await dispatcher.installSession(session, forDomain: .infotainment)

        let sendTask = Task { () throws -> Data in
            try await dispatcher.send(Data("getVehicleData".utf8), domain: .infotainment, timeout: .seconds(2))
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let outboundRequest = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        var response = UniversalMessage_RoutableMessage()
        stampRouting(on: &response, respondingTo: outboundRequest, domain: .infotainment)
        response.requestUuid = outboundRequest.uuid
        var status = UniversalMessage_MessageStatus()
        status.signedMessageFault = .rrorInsufficientPrivileges
        response.signedMessageStatus = status
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await sendTask.value
            XCTFail("expected protocol fault to be surfaced")
        } catch let Dispatcher.Error.decodingFailed(msg) {
            XCTAssertTrue(msg.contains("protocol fault"), "unexpected message: \(msg)")
            XCTAssertTrue(msg.contains("rrorInsufficientPrivileges"), "should name the fault: \(msg)")
        }

        await dispatcher.stop()
    }

    /// `operationStatus == .rror` without a fault code also must be surfaced.
    func testDispatcherSurfacesOperationStatusError() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .infotainment)
        await dispatcher.installSession(session, forDomain: .infotainment)

        let sendTask = Task { () throws -> Data in
            try await dispatcher.send(Data("x".utf8), domain: .infotainment, timeout: .seconds(2))
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let outboundRequest = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        var response = UniversalMessage_RoutableMessage()
        stampRouting(on: &response, respondingTo: outboundRequest, domain: .infotainment)
        response.requestUuid = outboundRequest.uuid
        var status = UniversalMessage_MessageStatus()
        status.operationStatus = .rror
        response.signedMessageStatus = status
        try await transport.enqueueInbound(response.serializedData())

        do {
            _ = try await sendTask.value
            XCTFail("expected operation error to be surfaced")
        } catch let Dispatcher.Error.decodingFailed(msg) {
            XCTAssertTrue(msg.contains("operation error"), "unexpected message: \(msg)")
        }

        await dispatcher.stop()
    }

    // MARK: - Per-domain routing semantics

    /// VCSEC signed responses are matched on `toDestination.routingAddress`
    /// rather than `requestUuid`. The real vehicle doesn't reliably echo
    /// requestUuid for VCSEC command responses, so Swift must route on the
    /// per-message random address instead — mirrors Go's `dispatcher.go:259`
    /// skip-UUID-for-VCSEC behavior.
    func testDispatcherRoutesVCSECByAddressWithEmptyRequestUuid() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .vehicleSecurity)
        await dispatcher.installSession(session, forDomain: .vehicleSecurity)

        let sendTask = Task { () throws -> Data in
            try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity, timeout: .seconds(2))
        }

        let outboundBytes = try await waitForFirstOutbound(transport)
        let outboundRequest = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        // Build a response with NO requestUuid. Dispatcher must still route it
        // back to the pending send by matching toDestination.routingAddress.
        var response = try UniversalMessage_RoutableMessage(
            serializedBytes: makeResponseBytes(
                respondingTo: outboundRequest,
                plaintext: Data("OK".utf8),
                counter: 1,
                sessionKey: makeSessionKey(),
                verifierName: Data("test_verifier".utf8),
                domain: .vehicleSecurity,
            ),
        )
        response.requestUuid = Data()
        try await transport.enqueueInbound(response.serializedData())

        let plaintext = try await sendTask.value
        XCTAssertEqual(plaintext, Data("OK".utf8))

        await dispatcher.stop()
    }

    /// Two concurrent Infotainment sends get disambiguated by `requestUuid`,
    /// not by routing address (which is stable for the domain).
    func testDispatcherInfotainmentUsesStableAddressAndUUIDMatching() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let session = makeSession(domain: .infotainment)
        await dispatcher.installSession(session, forDomain: .infotainment)

        // Fire two sequential sends and assert they use the SAME routing
        // address (Go semantics: infotainment reuses d.address).
        try await dispatcher.sendUnsignedNoReply(Data("a".utf8), domain: .infotainment)
        try await dispatcher.sendUnsignedNoReply(Data("b".utf8), domain: .infotainment)

        let outbound = await transport.sentMessages
        XCTAssertEqual(outbound.count, 2)
        let m0 = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        let m1 = try UniversalMessage_RoutableMessage(serializedBytes: outbound[1])
        guard
            case let .routingAddress(a0)? = m0.fromDestination.subDestination,
            case let .routingAddress(a1)? = m1.fromDestination.subDestination
        else {
            XCTFail("missing routingAddress"); return
        }
        XCTAssertEqual(a0, a1, "infotainment reuses a stable per-dispatcher address")
        XCTAssertNotEqual(m0.uuid, m1.uuid, "per-message uuids still rotate")

        await dispatcher.stop()
    }

    // MARK: - Fault-driven session resync

    /// When the vehicle attaches a fresh signed SessionInfo to any response
    /// (typically on a MessageFault), the inbound loop must HMAC-verify it
    /// and resync the installed session before completing the waiter. The
    /// waiter then observes the error and the NEXT send will use the new
    /// epoch/counter/sessionStart.
    func testDispatcherResyncsSessionFromInboundSessionInfo() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()
        let verifierName = Data("test_verifier".utf8)
        let sessionKey = makeSessionKey()

        // Install a fresh VCSEC session with a known epoch/counter.
        let session = VehicleSession(
            domain: .vehicleSecurity,
            verifierName: verifierName,
            localPublicKey: Data(repeating: 0x04, count: 65),
            sessionKey: sessionKey,
            epoch: Data(repeating: 0x11, count: 16),
            initialCounter: 5,
            clockTime: 0,
        )
        await dispatcher.installSession(session, forDomain: .vehicleSecurity)

        // Fire a send so there's a pending continuation to route the response to.
        let sendTask = Task { () throws -> Data in
            try await dispatcher.send(Data("lock".utf8), domain: .vehicleSecurity, timeout: .seconds(2))
        }
        let outboundBytes = try await waitForFirstOutbound(transport)
        let outboundRequest = try UniversalMessage_RoutableMessage(serializedBytes: outboundBytes)

        // Build a proactive-resync response carrying a new SessionInfo signed
        // by the same session key. The tag is HMAC keyed on the request uuid.
        var newInfo = Signatures_SessionInfo()
        newInfo.counter = 99
        newInfo.epoch = Data(repeating: 0xCC, count: 16)
        newInfo.clockTime = 777
        newInfo.publicKey = Data(repeating: 0x04, count: 65)
        let encoded = try newInfo.serializedData()
        let tag = try SessionNegotiator.computeSessionInfoTag(
            sessionKey: sessionKey,
            verifierName: verifierName,
            challenge: outboundRequest.uuid,
            encodedInfo: encoded,
        )
        var response = UniversalMessage_RoutableMessage()
        response.requestUuid = outboundRequest.uuid
        stampRouting(on: &response, respondingTo: outboundRequest, domain: .vehicleSecurity)
        response.payload = .sessionInfo(encoded)
        var hmacSig = Signatures_HMAC_Signature_Data()
        hmacSig.tag = tag
        var sig = Signatures_SignatureData()
        sig.sigType = .sessionInfoTag(hmacSig)
        response.subSigData = .signatureData(sig)
        try await transport.enqueueInbound(response.serializedData())

        // The waiter will fail verification (response is sessionInfo, not
        // aesGcmResponseData), but that's fine — we only care that the
        // session resynced BEFORE the waiter got the message.
        _ = try? await sendTask.value

#if DEBUG
        let c = await session.currentCounter
        let e = await session.currentEpoch
        XCTAssertEqual(c, 99, "counter should be updated from proactive SessionInfo")
        XCTAssertEqual(e, Data(repeating: 0xCC, count: 16), "epoch should be updated from proactive SessionInfo")
#endif

        await dispatcher.stop()
    }

    /// Two successive sends must use independent random routing addresses —
    /// matches the reference app's per-message randomization.
    func testDispatcherRoutingAddressVariesPerMessage() async throws {
        let transport = FakeTransport()
        let dispatcher = Dispatcher(transport: transport)
        try await dispatcher.start()

        try await dispatcher.sendUnsignedNoReply(Data("a".utf8), domain: .vehicleSecurity)
        try await dispatcher.sendUnsignedNoReply(Data("b".utf8), domain: .vehicleSecurity)

        let outbound = await transport.sentMessages
        XCTAssertEqual(outbound.count, 2)
        let m0 = try UniversalMessage_RoutableMessage(serializedBytes: outbound[0])
        let m1 = try UniversalMessage_RoutableMessage(serializedBytes: outbound[1])
        guard
            case let .routingAddress(a0)? = m0.fromDestination.subDestination,
            case let .routingAddress(a1)? = m1.fromDestination.subDestination
        else {
            XCTFail("missing routingAddress"); return
        }
        XCTAssertNotEqual(a0, a1, "each outbound message should get a fresh routing address")

        await dispatcher.stop()
    }
}
