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
//  LoginManagingTests.swift
//  ssoeTests
//
//  signToken and configuration(loginManager:) only need the LoginManaging
//  protocol, so a test double drives them without the OS login manager.
//

import XCTest
import AuthenticationServices

/// Minimal LoginManaging double with a software P-256 key.
final class FakeLoginManager: LoginManaging {
    var isDeviceRegistered = true
    var isUserRegistered = true
    var ssoTokens: [AnyHashable: Any]? = ["id_token": "header.payload.sig"]
    var extensionData: [AnyHashable: Any] = [
        "BaseURL": "https://idp.example.org/realms/test",
        "ClientID": "psso-client",
        "Issuer": "https://idp.example.org/realms/test",
        "Audience": "psso-aud",
    ]
    var authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod = .password
    var loginUserName: String? = "testuser"
    var jwksEndpointURL: URL?
    var reauthenticationError: Error?
    let signingKey: SecKey

    init() {
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ]
        signingKey = SecKeyCreateRandomKey(attrs as CFDictionary, nil)!
    }

    func key(for keyType: ASAuthorizationProviderExtensionKeyType) -> SecKey? {
        keyType == .sharedDeviceSigning ? signingKey : nil
    }

    func userNeedsReauthentication(completion: @escaping @Sendable (Error?) -> Void) {
        completion(reauthenticationError)
    }
}

final class LoginManagingTests: XCTestCase {

    private var vc: AuthenticationViewController!
    private var fake: FakeLoginManager!

    override func setUp() {
        super.setUp()
        vc = AuthenticationViewController(nibName: nil, bundle: nil)
        fake = FakeLoginManager()
        vc.loginManager = fake
    }

    override func tearDown() {
        vc = nil
        fake = nil
        super.tearDown()
    }

    func testConfigurationReadsExtensionDataThroughProtocol() {
        let config = vc.configuration(loginManager: fake)
        XCTAssertEqual(config.clientID, "psso-client")
        XCTAssertEqual(config.nonceEndpointURL.absoluteString, "https://idp.example.org/realms/test/psso/nonce")
    }

    func testSignTokenProducesVerifiableEnvelope() throws {
        let nonce = UUID()
        let signed = try XCTUnwrap(vc.signToken(token: "tok", tokenType: "id_token", loginManager: fake, nonce: nonce, clientId: "cid"))
        let parts = signed.split(separator: ".")
        XCTAssertEqual(parts.count, 2)

        let envelopeData = try XCTUnwrap(base64URLDecode(String(parts[0])))
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: envelopeData) as? [String: Any])
        XCTAssertEqual(envelope["username"] as? String, "testuser")
        XCTAssertEqual(envelope["nonce"] as? String, nonce.uuidString)
        XCTAssertEqual(envelope["token_type"] as? String, "id_token")
        XCTAssertEqual(envelope["secure_enclave"] as? Bool, false)

        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(fake.signingKey))
        XCTAssertEqual(envelope["kid"] as? String, vc.computeKid(from: publicKey))

        let signature = try XCTUnwrap(base64URLDecode(String(parts[1])))
        let dataToVerify = Data(String(parts[0]).utf8)
        XCTAssertTrue(SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, dataToVerify as CFData, signature as CFData, nil))
    }

    func testSignTokenReturnsNilWithoutUsername() {
        fake.loginUserName = nil
        XCTAssertNil(vc.signToken(token: "tok", tokenType: "id_token", loginManager: fake, nonce: UUID(), clientId: "cid"))
    }

    private func base64URLDecode(_ s: String) -> Data? {
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        return Data(base64Encoded: b64)
    }
}
