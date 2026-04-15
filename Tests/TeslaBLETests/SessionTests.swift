import Foundation
@testable import TeslaBLE
import XCTest

private extension Data {
    init?(hex: String) {
        let clean = hex.filter { !$0.isWhitespace }
        guard clean.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            guard let byte = UInt8(clean[idx ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        self.init(bytes)
    }
}

final class SessionTests: XCTestCase {
    // MARK: - Fixture loading

    private func loadJSON<T: Decodable>(_: T.Type, named filename: String) throws -> T {
        guard let url = Bundle.module.url(forResource: "Fixtures/session/\(filename)", withExtension: nil) else {
            XCTFail("Missing fixture: Fixtures/session/\(filename)")
            throw CocoaError(.fileNoSuchFile)
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(T.self, from: data)
    }

    // MARK: - Signing AAD

    private struct SigningAADFixture: Decodable {
        let description: String
        let cases: [Case]

        struct Case: Decodable {
            let name: String
            let domain: UInt32
            let verifierNameHex: String
            let epochHex: String
            let expiresAt: UInt32
            let counter: UInt32
            let flags: UInt32
            let expectedAadHex: String
        }
    }

    func testSigningAADVectors() throws {
        let fixture = try loadJSON(SigningAADFixture.self, named: "signing_aad_vectors.json")
        XCTAssertFalse(fixture.cases.isEmpty)

        for testCase in fixture.cases {
            var message = UniversalMessage_RoutableMessage()
            var destination = UniversalMessage_Destination()
            destination.domain = UniversalMessage_Domain(rawValue: Int(testCase.domain)) ?? .broadcast
            message.toDestination = destination
            message.flags = testCase.flags

            let verifierName = try XCTUnwrap(Data(hex: testCase.verifierNameHex))
            let epoch = try XCTUnwrap(Data(hex: testCase.epochHex))
            let expectedAAD = try XCTUnwrap(Data(hex: testCase.expectedAadHex))

            let actualAAD = try SessionMetadata.buildSigningAAD(
                message: message,
                verifierName: verifierName,
                epoch: epoch,
                counter: testCase.counter,
                expiresAt: testCase.expiresAt,
            )

            XCTAssertEqual(actualAAD, expectedAAD, "[\(testCase.name)] signing AAD mismatch")
        }
    }

    // MARK: - Response AAD

    private struct ResponseAADFixture: Decodable {
        let description: String
        let cases: [Case]

        struct Case: Decodable {
            let name: String
            let fromDomain: UInt32
            let verifierNameHex: String
            let requestIdHex: String
            let counter: UInt32
            let flags: UInt32
            let faultCode: UInt32
            let expectedAadHex: String
        }
    }

    func testResponseAADVectors() throws {
        let fixture = try loadJSON(ResponseAADFixture.self, named: "response_aad_vectors.json")
        XCTAssertFalse(fixture.cases.isEmpty)

        for testCase in fixture.cases {
            var message = UniversalMessage_RoutableMessage()
            var from = UniversalMessage_Destination()
            from.domain = UniversalMessage_Domain(rawValue: Int(testCase.fromDomain)) ?? .broadcast
            message.fromDestination = from
            message.flags = testCase.flags
            if testCase.faultCode != 0 {
                var status = UniversalMessage_MessageStatus()
                // Note: the generated enum case for "no error" is `.rrorNone`
                // (codegen quirk — protoc stripped the leading `E` from `ERROR_NONE`).
                status.signedMessageFault = UniversalMessage_MessageFault_E(rawValue: Int(testCase.faultCode)) ?? .rrorNone
                message.signedMessageStatus = status
            }

            let verifierName = try XCTUnwrap(Data(hex: testCase.verifierNameHex))
            let requestID = try XCTUnwrap(Data(hex: testCase.requestIdHex))
            let expectedAAD = try XCTUnwrap(Data(hex: testCase.expectedAadHex))

            let actualAAD = try SessionMetadata.buildResponseAAD(
                message: message,
                verifierName: verifierName,
                requestID: requestID,
                counter: testCase.counter,
            )

            XCTAssertEqual(actualAAD, expectedAAD, "[\(testCase.name)] response AAD mismatch")
        }
    }

    // MARK: - Round-trip sign/verify

    func testSignAndVerifyRoundtrip() throws {
        // Fixed deterministic session key and identity.
        let sessionKey = SessionKey(rawBytes: Data(repeating: 0x42, count: 16))
        let verifierName = Data("test_verifier".utf8)
        let epoch = Data(repeating: 0xAB, count: 16)
        let counter: UInt32 = 1
        let expiresAt: UInt32 = 60
        let localPublic = Data(repeating: 0x04, count: 65)

        // Build an outbound VCSEC request.
        var request = UniversalMessage_RoutableMessage()
        var dst = UniversalMessage_Destination()
        dst.domain = .vehicleSecurity
        request.toDestination = dst
        request.uuid = Data([0xDE, 0xAD, 0xBE, 0xEF])

        let plaintext = Data("lock command".utf8)
        try OutboundSigner.signGCM(
            plaintext: plaintext,
            message: &request,
            sessionKey: sessionKey,
            localPublicKey: localPublic,
            verifierName: verifierName,
            epoch: epoch,
            counter: counter,
            expiresAt: expiresAt,
        )

        // Assert the envelope is well-formed.
        guard case let .signatureData(sigData)? = request.subSigData else {
            XCTFail("request missing signature data"); return
        }
        guard case let .aesGcmPersonalizedData(gcm) = sigData.sigType else {
            XCTFail("wrong signature type"); return
        }
        XCTAssertEqual(gcm.epoch, epoch)
        XCTAssertEqual(gcm.counter, counter)
        XCTAssertEqual(gcm.expiresAt, expiresAt)
        XCTAssertEqual(gcm.nonce.count, 12)
        XCTAssertEqual(gcm.tag.count, 16)

        // Now pretend to be the vehicle: construct a response that echoes the
        // request's request-id, sealing a different plaintext with a fresh
        // deterministic nonce.
        let requestID = try XCTUnwrap(InboundVerifier.requestID(forSignedRequest: request))
        XCTAssertEqual(requestID.first, UInt8(Signatures_SignatureType.aesGcmPersonalized.rawValue))
        XCTAssertEqual(requestID.count, 17, "requestID = [type_byte] + 16-byte GCM tag")

        let responseCounter: UInt32 = 1
        let responsePlaintext = Data("OK".utf8)

        var response = UniversalMessage_RoutableMessage()
        var from = UniversalMessage_Destination()
        from.domain = .vehicleSecurity
        response.fromDestination = from
        response.requestUuid = request.uuid

        let responseAAD = try SessionMetadata.buildResponseAAD(
            message: response,
            verifierName: verifierName,
            requestID: requestID,
            counter: responseCounter,
        )
        let fixedNonce = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B])
        let responseSealed = try MessageAuthenticator.sealFixed(
            plaintext: responsePlaintext,
            associatedData: responseAAD,
            nonce: fixedNonce,
            sessionKey: sessionKey,
        )
        var responseGCM = Signatures_AES_GCM_Response_Signature_Data()
        responseGCM.nonce = fixedNonce
        responseGCM.counter = responseCounter
        responseGCM.tag = responseSealed.tag
        var responseSigData = Signatures_SignatureData()
        responseSigData.sigType = .aesGcmResponseData(responseGCM)
        response.subSigData = .signatureData(responseSigData)
        response.payload = .protobufMessageAsBytes(responseSealed.ciphertext)

        // Verify with InboundVerifier.
        let opened = try InboundVerifier.openGCMResponse(
            message: response,
            sessionKey: sessionKey,
            verifierName: verifierName,
            requestID: requestID,
        )
        XCTAssertEqual(opened.counter, responseCounter)
        XCTAssertEqual(opened.plaintext, responsePlaintext)
    }

    // MARK: - VehicleSession state transitions

    private func makeTestSession(initialCounter: UInt32 = 0) -> VehicleSession {
        VehicleSession(
            domain: .vehicleSecurity,
            verifierName: Data("test_verifier".utf8),
            localPublicKey: Data(repeating: 0x04, count: 65),
            sessionKey: SessionKey(rawBytes: Data(repeating: 0x42, count: 16)),
            epoch: Data(repeating: 0xAB, count: 16),
            initialCounter: initialCounter,
        )
    }

    private func makeVCSECRequest() -> UniversalMessage_RoutableMessage {
        var m = UniversalMessage_RoutableMessage()
        var d = UniversalMessage_Destination()
        d.domain = .vehicleSecurity
        m.toDestination = d
        return m
    }

    func testVehicleSessionSignIncrementsCounter() async throws {
        let session = makeTestSession(initialCounter: 10)
        var message = makeVCSECRequest()
        try await session.sign(plaintext: Data("a".utf8), into: &message, expiresIn: 60)

#if DEBUG
        let counterAfter = await session.currentCounter
        XCTAssertEqual(counterAfter, 11, "counter must increment by 1 per sign")
#endif

        guard case let .signatureData(s)? = message.subSigData,
              case let .aesGcmPersonalizedData(gcm) = s.sigType
        else {
            XCTFail("missing envelope"); return
        }
        XCTAssertEqual(gcm.counter, 11)
    }

    func testVehicleSessionCounterRolloverThrows() async throws {
        let session = makeTestSession(initialCounter: UInt32.max)
        var message = makeVCSECRequest()
        do {
            try await session.sign(plaintext: Data("a".utf8), into: &message, expiresIn: 60)
            XCTFail("expected rollover throw")
        } catch VehicleSession.Error.counterRollover {
            // ok
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testVehicleSessionVerifyAcceptsResponse() async throws {
        let session = makeTestSession()

        // Construct a signed request we'll later use as the "request" for
        // requestID computation.
        var request = makeVCSECRequest()
        try await session.sign(plaintext: Data("req".utf8), into: &request, expiresIn: 60)
        let requestID = try XCTUnwrap(InboundVerifier.requestID(forSignedRequest: request))

        // Fabricate a response sealed by the same session key.
        let responseCounter: UInt32 = 5
        var response = UniversalMessage_RoutableMessage()
        var from = UniversalMessage_Destination()
        from.domain = .vehicleSecurity
        response.fromDestination = from
        let aad = try SessionMetadata.buildResponseAAD(
            message: response,
            verifierName: Data("test_verifier".utf8),
            requestID: requestID,
            counter: responseCounter,
        )
        let nonce = Data([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
        let sealed = try MessageAuthenticator.sealFixed(
            plaintext: Data("OK".utf8),
            associatedData: aad,
            nonce: nonce,
            sessionKey: SessionKey(rawBytes: Data(repeating: 0x42, count: 16)),
        )
        var gcm = Signatures_AES_GCM_Response_Signature_Data()
        gcm.nonce = nonce
        gcm.counter = responseCounter
        gcm.tag = sealed.tag
        var sigData = Signatures_SignatureData()
        sigData.sigType = .aesGcmResponseData(gcm)
        response.subSigData = .signatureData(sigData)
        response.payload = .protobufMessageAsBytes(sealed.ciphertext)

        // Replay detection lives at the dispatcher layer (request-token
        // routing, matching Go's per-receiver antireplay window), not here;
        // `verify` must accept the same counter on repeat calls because the
        // vehicle only guarantees monotonicity per request ID.
        let first = try await session.verify(response: response, requestID: requestID)
        XCTAssertEqual(first, Data("OK".utf8))
        let second = try await session.verify(response: response, requestID: requestID)
        XCTAssertEqual(second, Data("OK".utf8))
    }

    func testVehicleSessionResyncResetsState() async {
        let session = makeTestSession(initialCounter: 50)
        let newEpoch = Data(repeating: 0xCD, count: 16)
        var info = Signatures_SessionInfo()
        info.epoch = newEpoch
        info.counter = 0
        info.clockTime = 1234
        let handshake = Date(timeIntervalSince1970: 2_000_000)
        await session.resync(fromSessionInfo: info, handshakeDate: handshake)

#if DEBUG
        let c = await session.currentCounter
        let e = await session.currentEpoch
        let start = await session.currentSessionStart
        XCTAssertEqual(c, 0)
        XCTAssertEqual(e, newEpoch)
        XCTAssertEqual(
            start.timeIntervalSince1970,
            handshake.timeIntervalSince1970 - 1234,
            accuracy: 0.001,
            "sessionStart must rewind by the vehicle-advertised clockTime",
        )
#endif
    }

    func testVehicleSessionSignWritesEpochRelativeExpiresAt() async throws {
        // Pretend the handshake happened with vehicle clock = 10_000 seconds
        // into the epoch. Any signed command should be stamped with
        // `floor(10_000 + ttl)` seconds since that epoch started — matching
        // Go's `signer.go` `encryptWithCounter` formula.
        let clockTime: UInt32 = 10000
        let ttl: TimeInterval = 5
        let handshake = Date()
        let session = VehicleSession(
            domain: .vehicleSecurity,
            verifierName: Data("test_verifier".utf8),
            localPublicKey: Data(repeating: 0x04, count: 65),
            sessionKey: SessionKey(rawBytes: Data(repeating: 0x42, count: 16)),
            epoch: Data(repeating: 0xAB, count: 16),
            initialCounter: 0,
            clockTime: clockTime,
            handshakeDate: handshake,
        )

        var message = makeVCSECRequest()
        try await session.sign(plaintext: Data("go".utf8), into: &message, expiresIn: ttl)

        guard case let .signatureData(s)? = message.subSigData,
              case let .aesGcmPersonalizedData(gcm) = s.sigType
        else {
            XCTFail("missing envelope"); return
        }

        // Expected ≈ clockTime + ttl; small +/- slack for whatever time
        // elapsed between the init() call and the sign() call.
        let expected = Double(clockTime) + ttl
        let actual = Double(gcm.expiresAt)
        XCTAssertGreaterThanOrEqual(actual, expected - 1)
        XCTAssertLessThanOrEqual(actual, expected + 2)
    }

    // MARK: - SessionNegotiator

    func testSessionNegotiatorBuildsWellFormedRequest() {
        let publicKey = Data(repeating: 0x04, count: 65)
        let message = SessionNegotiator.buildRequest(
            domain: .vehicleSecurity,
            publicKey: publicKey,
            uuid: Data([0xDE, 0xAD]),
            fromRoutingAddress: Data(repeating: 0x11, count: 16),
        )
        XCTAssertEqual(message.toDestination.domain, .vehicleSecurity)
        XCTAssertEqual(message.uuid, Data([0xDE, 0xAD]))
        guard case let .sessionInfoRequest(req)? = message.payload else {
            XCTFail("wrong payload"); return
        }
        XCTAssertEqual(req.publicKey, publicKey)
        XCTAssertTrue(req.challenge.isEmpty)
    }

    func testSessionNegotiatorValidatesGoodResponse() throws {
        let sessionKey = SessionKey(rawBytes: Data(repeating: 0x11, count: 16))
        let verifierName = Data("test_verifier".utf8)
        let challenge = Data([0, 1, 2, 3, 4, 5, 6, 7])

        // Pretend the vehicle serialized a SessionInfo protobuf.
        var info = Signatures_SessionInfo()
        info.counter = 7
        info.publicKey = Data(repeating: 0x04, count: 65)
        info.epoch = Data(repeating: 0xAB, count: 16)
        info.clockTime = 12345
        let encoded = try info.serializedData()

        // Compute the tag we'd expect.
        let expectedTag = try SessionNegotiator.computeSessionInfoTag(
            sessionKey: sessionKey,
            verifierName: verifierName,
            challenge: challenge,
            encodedInfo: encoded,
        )

        // Build the response message.
        var response = UniversalMessage_RoutableMessage()
        response.payload = .sessionInfo(encoded)
        var sig = Signatures_SignatureData()
        var hmac = Signatures_HMAC_Signature_Data()
        hmac.tag = expectedTag
        sig.sigType = .sessionInfoTag(hmac)
        response.subSigData = .signatureData(sig)

        let decoded = try SessionNegotiator.validateResponse(
            message: response,
            sessionKey: sessionKey,
            verifierName: verifierName,
            challenge: challenge,
        )
        XCTAssertEqual(decoded.counter, 7)
        XCTAssertEqual(decoded.clockTime, 12345)
    }

    func testSessionNegotiatorRejectsTamperedTag() throws {
        let sessionKey = SessionKey(rawBytes: Data(repeating: 0x11, count: 16))
        let verifierName = Data("test_verifier".utf8)
        let challenge = Data([0, 1, 2, 3, 4, 5, 6, 7])

        var info = Signatures_SessionInfo()
        info.counter = 7
        info.epoch = Data(repeating: 0xAB, count: 16)
        let encoded = try info.serializedData()

        var expectedTag = try SessionNegotiator.computeSessionInfoTag(
            sessionKey: sessionKey,
            verifierName: verifierName,
            challenge: challenge,
            encodedInfo: encoded,
        )
        expectedTag[0] ^= 0x01 // flip a bit

        var response = UniversalMessage_RoutableMessage()
        response.payload = .sessionInfo(encoded)
        var sig = Signatures_SignatureData()
        var hmac = Signatures_HMAC_Signature_Data()
        hmac.tag = expectedTag
        sig.sigType = .sessionInfoTag(hmac)
        response.subSigData = .signatureData(sig)

        XCTAssertThrowsError(try SessionNegotiator.validateResponse(
            message: response,
            sessionKey: sessionKey,
            verifierName: verifierName,
            challenge: challenge,
        )) { error in
            XCTAssertEqual(error as? SessionNegotiator.Error, .hmacMismatch)
        }
    }
}
