/* Copyright 2025 University of Oslo, Norway
 # This file is part of the Weblogin SSO Extension codebase.
 #
 # The Weblogin SSO Extension is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this extension; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/

//
//  StepUpJWTTests.swift
//  ssoeTests
//
//  verifyStepUpJWT against a JWKS file: the signed step-up token the IdP puts
//  on its reauthentication page must carry the challenge from the last envelope.
//

import XCTest
import CryptoKit
import Security

final class StepUpJWTTests: XCTestCase {

    private let issuer = "https://idp.example.org/realms/test"
    private let audience = "psso-aud"
    private let challenge = "armed-challenge"

    private var vc: AuthenticationViewController!
    private var fake: FakeLoginManager!
    private var jwksFile: URL!
    private let ecKey = P256.Signing.PrivateKey()
    private var rsaKey: SecKey!

    override func setUpWithError() throws {
        try super.setUpWithError()
        vc = AuthenticationViewController(nibName: nil, bundle: nil)
        fake = FakeLoginManager()
        vc.loginManager = fake
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        rsaKey = try XCTUnwrap(SecKeyCreateRandomKey(attrs as CFDictionary, nil))
        jwksFile = FileManager.default.temporaryDirectory.appendingPathComponent("jwks-\(UUID().uuidString).json")
        try writeJWKS([ecJWK(kid: "ec-1"), try rsaJWK(kid: "rsa-1")])
        fake.jwksEndpointURL = jwksFile
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: jwksFile)
        vc = nil
        fake = nil
        try super.tearDownWithError()
    }

    // MARK: accepted

    func testAcceptsES256TokenCarryingTheArmedChallenge() async throws {
        let ok = await verify(try es256(claims()))
        XCTAssertTrue(ok)
    }

    func testAcceptsRS256TokenCarryingTheArmedChallenge() async throws {
        let ok = await verify(try rs256(claims()))
        XCTAssertTrue(ok)
    }

    func testAcceptsAudienceArrayContainingTheConfiguredAudience() async throws {
        let ok = await verify(try es256(claims(["aud": ["other", audience]])))
        XCTAssertTrue(ok)
    }

    // MARK: rejected

    func testRejectsAnotherChallenge() async throws {
        let ok = await verify(try es256(claims(["reauth_challenge": "stale-challenge"])))
        XCTAssertFalse(ok)
    }

    func testRejectsMissingChallengeClaim() async throws {
        var c = claims()
        c.removeValue(forKey: "reauth_challenge")
        let ok = await verify(try es256(c))
        XCTAssertFalse(ok)
    }

    func testRejectsWhenNoChallengeIsArmed() async throws {
        let ok = await vc.verifyStepUpJWT(stepupToken: try es256(claims(["reauth_challenge": ""])), localChallenge: "", loginManager: fake)
        XCTAssertFalse(ok)
    }

    func testRejectsSignatureFromKeyOutsideJWKS() async throws {
        let ok = await verify(try es256(claims(), key: P256.Signing.PrivateKey()))
        XCTAssertFalse(ok)
    }

    func testRejectsUnknownKid() async throws {
        let ok = await verify(try es256(claims(), kid: "rotated-away"))
        XCTAssertFalse(ok)
    }

    func testRejectsAlgNone() async throws {
        let token = jws(header: ["alg": "none", "kid": "ec-1"], claims: claims(), signature: Data())
        let ok = await verify(token)
        XCTAssertFalse(ok)
    }

    func testRejectsHS256SignedWithThePublicKey() async throws {
        let header: [String: Any] = ["alg": "HS256", "kid": "rsa-1"]
        let input = signingInput(header: header, claims: claims())
        let mac = HMAC<SHA256>.authenticationCode(for: Data(input.utf8), using: SymmetricKey(data: ecKey.publicKey.x963Representation))
        let ok = await verify(input + "." + vc.base64URLEncode(Data(mac)))
        XCTAssertFalse(ok)
    }

    func testRejectsExpiredToken() async throws {
        let past = Date().timeIntervalSince1970 - 120
        let ok = await verify(try es256(claims(["exp": past])))
        XCTAssertFalse(ok)
    }

    func testRejectsTokenWithoutExp() async throws {
        var c = claims()
        c.removeValue(forKey: "exp")
        let ok = await verify(try es256(c))
        XCTAssertFalse(ok)
    }

    func testRejectsOtherIssuer() async throws {
        let ok = await verify(try es256(claims(["iss": "https://evil.example.org/realms/test"])))
        XCTAssertFalse(ok)
    }

    func testRejectsOtherAudience() async throws {
        let ok = await verify(try es256(claims(["aud": "someone-else"])))
        XCTAssertFalse(ok)
    }

    func testRejectsMalformedToken() async {
        let ok = await verify("not-a-jwt")
        XCTAssertFalse(ok)
    }

    // MARK: challenge arming

    func testSignTokenArmsAFreshChallengeAndSendsIt() throws {
        let first = try envelope(vc.signToken(token: "tok", tokenType: "id_token", loginManager: fake, nonce: UUID(), clientId: "cid"))
        let armed = vc.reauthChallenge
        XCTAssertFalse(armed.isEmpty)
        XCTAssertEqual(first["reauth_challenge"] as? String, armed)

        let second = try envelope(vc.signToken(token: "tok", tokenType: "id_token", loginManager: fake, nonce: UUID(), clientId: "cid"))
        XCTAssertNotEqual(vc.reauthChallenge, armed)
        XCTAssertEqual(second["reauth_challenge"] as? String, vc.reauthChallenge)
    }

    // MARK: helpers

    private func verify(_ token: String) async -> Bool {
        await vc.verifyStepUpJWT(stepupToken: token, localChallenge: challenge, loginManager: fake)
    }

    private func claims(_ overrides: [String: Any] = [:]) -> [String: Any] {
        let now = Date().timeIntervalSince1970
        var c: [String: Any] = [
            "iss": issuer, "aud": audience, "iat": now, "exp": now + 60, "reauth_challenge": challenge,
        ]
        c.merge(overrides) { $1 }
        return c
    }

    private func signingInput(header: [String: Any], claims: [String: Any]) -> String {
        func seg(_ obj: [String: Any]) -> String {
            vc.base64URLEncode(try! JSONSerialization.data(withJSONObject: obj))
        }
        return seg(header) + "." + seg(claims)
    }

    private func jws(header: [String: Any], claims: [String: Any], signature: Data) -> String {
        signingInput(header: header, claims: claims) + "." + vc.base64URLEncode(signature)
    }

    private func es256(_ claims: [String: Any], kid: String = "ec-1", key: P256.Signing.PrivateKey? = nil) throws -> String {
        let header: [String: Any] = ["alg": "ES256", "kid": kid, "typ": "JWT"]
        let input = signingInput(header: header, claims: claims)
        let sig = try (key ?? ecKey).signature(for: Data(input.utf8))
        return input + "." + vc.base64URLEncode(sig.rawRepresentation)
    }

    private func rs256(_ claims: [String: Any]) throws -> String {
        let header: [String: Any] = ["alg": "RS256", "kid": "rsa-1", "typ": "JWT"]
        let input = signingInput(header: header, claims: claims)
        let sig = try XCTUnwrap(SecKeyCreateSignature(rsaKey, .rsaSignatureMessagePKCS1v15SHA256, Data(input.utf8) as CFData, nil)) as Data
        return input + "." + vc.base64URLEncode(sig)
    }

    private func ecJWK(kid: String) -> [String: Any] {
        let raw = ecKey.publicKey.rawRepresentation  // X || Y
        return ["kty": "EC", "crv": "P-256", "use": "sig", "kid": kid,
                "x": vc.base64URLEncode(raw.prefix(32)), "y": vc.base64URLEncode(raw.suffix(32))]
    }

    /// Reads n and e out of the PKCS#1 RSAPublicKey DER that Security exports.
    private func rsaJWK(kid: String) throws -> [String: Any] {
        let pub = try XCTUnwrap(SecKeyCopyPublicKey(rsaKey))
        let der = [UInt8](try XCTUnwrap(SecKeyCopyExternalRepresentation(pub, nil)) as Data)
        var i = 0
        func readLength() -> Int {
            let first = Int(der[i]); i += 1
            guard first & 0x80 != 0 else { return first }
            var len = 0
            for _ in 0..<(first & 0x7f) { len = len << 8 | Int(der[i]); i += 1 }
            return len
        }
        func readInteger() -> Data {
            precondition(der[i] == 0x02); i += 1
            let len = readLength()
            defer { i += len }
            return Data(der[i..<i + len]).drop { $0 == 0 }
        }
        precondition(der[i] == 0x30); i += 1
        _ = readLength()
        let n = readInteger(), e = readInteger()
        return ["kty": "RSA", "use": "sig", "kid": kid, "n": vc.base64URLEncode(n), "e": vc.base64URLEncode(e)]
    }

    private func writeJWKS(_ keys: [[String: Any]]) throws {
        try JSONSerialization.data(withJSONObject: ["keys": keys]).write(to: jwksFile)
    }

    private func envelope(_ signed: String?) throws -> [String: Any] {
        let part = try XCTUnwrap(signed?.split(separator: ".").first)
        let data = try XCTUnwrap(vc.base64URLDecode(String(part)))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}
