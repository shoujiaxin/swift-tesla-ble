import Foundation

/// Handshake helpers that construct a `SessionInfoRequest` and validate the
/// vehicle's signed `SessionInfo` response.
///
/// The handshake itself is a normal request/response flowing through the
/// dispatcher — this module only handles message construction on the way
/// out and HMAC verification on the way in. Mirrors `SessionInfoHMAC` in
/// `internal/authentication/native.go` and `UpdateSignedSessionInfo` in
/// `internal/authentication/signer.go`.
///
/// Subtle ordering constraint. The `SessionInfo` response carries the
/// vehicle's ephemeral P-256 public key, and its HMAC tag is keyed off the
/// session key that is derived from the ECDH between THAT key and our local
/// private scalar. In other words we cannot verify the HMAC until we have
/// finished the ECDH — and the ECDH itself trusts the peer public key that
/// the (unverified) response blob just handed us. The authenticator here
/// closes that loop: we derive the session key speculatively, HMAC-verify
/// over the encoded response using that speculative key, and only then
/// commit. A man-in-the-middle who substituted a different public key
/// would produce a different session key, the HMAC would fail to match
/// the vehicle-signed tag, and `validateResponse` throws `.hmacMismatch`.
/// The root of trust is that the peer public key is ultimately authorized
/// by a key previously enrolled on the vehicle; this function only
/// validates that the SessionInfo came from that party.
enum SessionNegotiator {
    enum Error: Swift.Error, Equatable {
        case missingPayload
        case wrongSessionType
        case hmacMismatch
        case decodeFailed(String)
    }

    /// Build an outbound `SessionInfoRequest` for the given domain. Caller is
    /// responsible for generating a fresh `challenge` (8 random bytes is
    /// standard — see `getGCMVerifierAndSigner` in peer_test.go).
    static func buildRequest(
        domain: UniversalMessage_Domain,
        publicKey: Data,
        challenge: Data,
        uuid: Data = Data(),
        fromRoutingAddress: Data,
    ) -> UniversalMessage_RoutableMessage {
        var request = UniversalMessage_SessionInfoRequest()
        request.publicKey = publicKey
        request.challenge = challenge

        var destination = UniversalMessage_Destination()
        destination.domain = domain

        // Vehicles fold `fromDestination.routingAddress` into the session-info
        // HMAC metadata. Omitting it causes the car to answer with an
        // unsigned SessionInfo broadcast that can never complete a handshake.
        var fromDestination = UniversalMessage_Destination()
        fromDestination.routingAddress = fromRoutingAddress

        var message = UniversalMessage_RoutableMessage()
        message.toDestination = destination
        message.fromDestination = fromDestination
        message.uuid = uuid
        message.payload = .sessionInfoRequest(request)
        return message
    }

    /// Validate a vehicle-supplied `SessionInfo` response. Returns the decoded
    /// `Signatures_SessionInfo` on success.
    ///
    /// Verification steps:
    /// 1. Extract the `sessionInfo` payload bytes from the response.
    /// 2. Extract the HMAC tag from the `sessionInfoTag` signature sub-data.
    /// 3. Recompute `SessionInfoHMAC(verifierName, challenge, encodedInfo)`
    ///    using `MetadataHash.hmacContext(sessionKey:label:"session info")`.
    /// 4. Constant-time compare against the supplied tag.
    /// 5. Decode the protobuf.
    static func validateResponse(
        message: UniversalMessage_RoutableMessage,
        sessionKey: SessionKey,
        verifierName: Data,
        challenge: Data,
    ) throws -> Signatures_SessionInfo {
        guard case let .sessionInfo(encodedInfo)? = message.payload else {
            throw Error.missingPayload
        }
        guard case let .signatureData(sigData)? = message.subSigData else {
            throw Error.wrongSessionType
        }
        guard case let .sessionInfoTag(hmacSig)? = sigData.sigType else {
            throw Error.wrongSessionType
        }

        let expectedTag = try computeSessionInfoTag(
            sessionKey: sessionKey,
            verifierName: verifierName,
            challenge: challenge,
            encodedInfo: encodedInfo,
        )
        guard Self.constantTimeEqual(expectedTag, hmacSig.tag) else {
            throw Error.hmacMismatch
        }

        do {
            return try Signatures_SessionInfo(serializedBytes: encodedInfo)
        } catch {
            throw Error.decodeFailed(String(describing: error))
        }
    }

    /// Compute the session-info HMAC tag. Exposed for tests.
    static func computeSessionInfoTag(
        sessionKey: SessionKey,
        verifierName: Data,
        challenge: Data,
        encodedInfo: Data,
    ) throws -> Data {
        var builder = MetadataHash.hmacContext(sessionKey: sessionKey, label: "session info")
        try builder.add(
            tagRaw: UInt8(Signatures_Tag.signatureType.rawValue),
            value: Data([UInt8(Signatures_SignatureType.hmac.rawValue)]),
        )
        try builder.add(
            tagRaw: UInt8(Signatures_Tag.personalization.rawValue),
            value: verifierName,
        )
        try builder.add(
            tagRaw: UInt8(Signatures_Tag.challenge.rawValue),
            value: challenge,
        )
        return builder.checksum(over: encodedInfo)
    }

    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0 ..< a.count {
            diff |= a[a.index(a.startIndex, offsetBy: i)] ^ b[b.index(b.startIndex, offsetBy: i)]
        }
        return diff == 0
    }
}
