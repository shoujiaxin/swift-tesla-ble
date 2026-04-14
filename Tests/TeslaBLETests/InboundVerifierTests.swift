import Foundation
@testable import TeslaBLE
import XCTest

final class InboundVerifierTests: XCTestCase {
    // MARK: - requestID

    func testRequestIDReturnsNilForUnsignedRequest() {
        var message = UniversalMessage_RoutableMessage()
        var dst = UniversalMessage_Destination()
        dst.domain = .vehicleSecurity
        message.toDestination = dst
        // No subSigData — unsigned.
        XCTAssertNil(InboundVerifier.requestID(forSignedRequest: message))
    }

    func testRequestIDReturnsNilForSessionInfoTaggedRequest() {
        // sessionInfoTag is a valid sig type but not one of the handled cases
        // in InboundVerifier.requestID — should hit the default branch.
        var message = UniversalMessage_RoutableMessage()
        var dst = UniversalMessage_Destination()
        dst.domain = .vehicleSecurity
        message.toDestination = dst

        var hmacTag = Signatures_HMAC_Signature_Data()
        hmacTag.tag = Data(repeating: 0xAA, count: 16)
        var sig = Signatures_SignatureData()
        sig.sigType = .sessionInfoTag(hmacTag)
        message.subSigData = .signatureData(sig)

        XCTAssertNil(InboundVerifier.requestID(forSignedRequest: message))
    }

    func testRequestIDHMACPersonalizedVCSECTruncatesTagTo16Bytes() throws {
        var message = UniversalMessage_RoutableMessage()
        var dst = UniversalMessage_Destination()
        dst.domain = .vehicleSecurity
        message.toDestination = dst

        let fullTag = Data((0 ..< 32).map { UInt8($0) })
        var hmac = Signatures_HMAC_Personalized_Signature_Data()
        hmac.tag = fullTag
        var sig = Signatures_SignatureData()
        sig.sigType = .hmacPersonalizedData(hmac)
        message.subSigData = .signatureData(sig)

        let id = try XCTUnwrap(InboundVerifier.requestID(forSignedRequest: message))
        XCTAssertEqual(id.count, 17, "[type byte] + 16-byte truncated tag")
        XCTAssertEqual(id.first, UInt8(Signatures_SignatureType.hmacPersonalized.rawValue))
        XCTAssertEqual(id.dropFirst(), fullTag.prefix(16))
    }

    func testRequestIDHMACPersonalizedNonVCSECKeepsFullTag() throws {
        var message = UniversalMessage_RoutableMessage()
        var dst = UniversalMessage_Destination()
        dst.domain = .infotainment
        message.toDestination = dst

        let fullTag = Data((0 ..< 32).map { UInt8($0) })
        var hmac = Signatures_HMAC_Personalized_Signature_Data()
        hmac.tag = fullTag
        var sig = Signatures_SignatureData()
        sig.sigType = .hmacPersonalizedData(hmac)
        message.subSigData = .signatureData(sig)

        let id = try XCTUnwrap(InboundVerifier.requestID(forSignedRequest: message))
        XCTAssertEqual(id.count, 33, "[type byte] + full 32-byte tag")
        XCTAssertEqual(id.first, UInt8(Signatures_SignatureType.hmacPersonalized.rawValue))
        XCTAssertEqual(id.dropFirst(), fullTag)
    }

    func testRequestIDHMACPersonalizedShortTagUnchanged() throws {
        // Tag already <= 16 bytes: VCSEC branch should leave it alone.
        var message = UniversalMessage_RoutableMessage()
        var dst = UniversalMessage_Destination()
        dst.domain = .vehicleSecurity
        message.toDestination = dst

        let shortTag = Data(repeating: 0x55, count: 12)
        var hmac = Signatures_HMAC_Personalized_Signature_Data()
        hmac.tag = shortTag
        var sig = Signatures_SignatureData()
        sig.sigType = .hmacPersonalizedData(hmac)
        message.subSigData = .signatureData(sig)

        let id = try XCTUnwrap(InboundVerifier.requestID(forSignedRequest: message))
        XCTAssertEqual(id.count, 13)
        XCTAssertEqual(id.dropFirst(), shortTag)
    }

    // MARK: - openGCMResponse error paths

    private let sessionKey = SessionKey(rawBytes: Data(repeating: 0x42, count: 16))
    private let verifierName = Data("test_verifier".utf8)
    private let requestID = Data([UInt8(Signatures_SignatureType.aesGcmPersonalized.rawValue)]) + Data(repeating: 0xCC, count: 16)

    private func makeBaseResponse() -> UniversalMessage_RoutableMessage {
        var msg = UniversalMessage_RoutableMessage()
        var from = UniversalMessage_Destination()
        from.domain = .vehicleSecurity
        msg.fromDestination = from
        return msg
    }

    func testOpenGCMResponseMissingSignatureData() {
        var msg = makeBaseResponse()
        msg.payload = .protobufMessageAsBytes(Data([0x01, 0x02]))
        // No subSigData.

        XCTAssertThrowsError(
            try InboundVerifier.openGCMResponse(
                message: msg,
                sessionKey: sessionKey,
                verifierName: verifierName,
                requestID: requestID,
            ),
        ) { error in
            XCTAssertEqual(error as? InboundVerifier.Error, .missingSignatureData)
        }
    }

    func testOpenGCMResponseWrongSigType() {
        var msg = makeBaseResponse()
        msg.payload = .protobufMessageAsBytes(Data([0x01]))
        // Attach an HMAC-personalized signature (not GCM response).
        var hmac = Signatures_HMAC_Personalized_Signature_Data()
        hmac.tag = Data(repeating: 0x11, count: 16)
        var sig = Signatures_SignatureData()
        sig.sigType = .hmacPersonalizedData(hmac)
        msg.subSigData = .signatureData(sig)

        XCTAssertThrowsError(
            try InboundVerifier.openGCMResponse(
                message: msg,
                sessionKey: sessionKey,
                verifierName: verifierName,
                requestID: requestID,
            ),
        ) { error in
            XCTAssertEqual(error as? InboundVerifier.Error, .notAnAESGCMResponse)
        }
    }

    func testOpenGCMResponseMissingPayload() {
        var msg = makeBaseResponse()
        // Valid aesGcmResponse sig but no payload bytes.
        var gcm = Signatures_AES_GCM_Response_Signature_Data()
        gcm.nonce = Data(repeating: 0x01, count: 12)
        gcm.counter = 1
        gcm.tag = Data(repeating: 0x02, count: 16)
        var sig = Signatures_SignatureData()
        sig.sigType = .aesGcmResponseData(gcm)
        msg.subSigData = .signatureData(sig)

        XCTAssertThrowsError(
            try InboundVerifier.openGCMResponse(
                message: msg,
                sessionKey: sessionKey,
                verifierName: verifierName,
                requestID: requestID,
            ),
        ) { error in
            XCTAssertEqual(error as? InboundVerifier.Error, .missingPayload)
        }
    }

    func testOpenGCMResponseAuthenticationFailureOnBadTag() throws {
        // Seal a real response, then replace the authentication tag with
        // zeros. AES-GCM verification rejects it with
        // CryptoKitError.authenticationFailure, which MessageAuthenticator
        // maps to .authenticationFailure, which InboundVerifier re-throws as
        // its own .authenticationFailure — previously uncovered.
        let responseCounter: UInt32 = 7
        var msg = makeBaseResponse()

        let aad = try SessionMetadata.buildResponseAAD(
            message: msg,
            verifierName: verifierName,
            requestID: requestID,
            counter: responseCounter,
        )
        let nonce = Data(repeating: 0x07, count: 12)
        let sealed = try MessageAuthenticator.sealFixed(
            plaintext: Data("OK".utf8),
            associatedData: aad,
            nonce: nonce,
            sessionKey: sessionKey,
        )

        var gcm = Signatures_AES_GCM_Response_Signature_Data()
        gcm.nonce = nonce
        gcm.counter = responseCounter
        gcm.tag = Data(repeating: 0x00, count: 16) // wrong tag
        var sig = Signatures_SignatureData()
        sig.sigType = .aesGcmResponseData(gcm)
        msg.subSigData = .signatureData(sig)
        msg.payload = .protobufMessageAsBytes(sealed.ciphertext)

        XCTAssertThrowsError(
            try InboundVerifier.openGCMResponse(
                message: msg,
                sessionKey: sessionKey,
                verifierName: verifierName,
                requestID: requestID,
            ),
        ) { error in
            XCTAssertEqual(error as? InboundVerifier.Error, .authenticationFailure)
        }
    }
}
