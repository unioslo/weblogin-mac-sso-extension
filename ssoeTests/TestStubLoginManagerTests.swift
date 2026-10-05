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
//  TestStubLoginManagerTests.swift
//  ssoeTests
//
//  The stub decodes psso-test-stub.json and signs with a software key.
//  ssoeTests compiles with TESTSTUBS, so the stub exists here.
//

import XCTest
import AuthenticationServices

final class TestStubLoginManagerTests: XCTestCase {

    private func freshKey() throws -> SecKey {
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ]
        return try XCTUnwrap(SecKeyCreateRandomKey(attrs as CFDictionary, nil))
    }

    /// X9.63 private key: 04 || X || Y || K for a P-256 key.
    private func x963Base64(_ key: SecKey) throws -> String {
        let data = try XCTUnwrap(SecKeyCopyExternalRepresentation(key, nil) as Data?)
        XCTAssertEqual(data.count, 97)
        return data.base64EncodedString()
    }

    private func freshX963Base64() throws -> String {
        try x963Base64(try freshKey())
    }

    private func json(reauthentication: String = "succeed", key: String) -> Data {
        let text = """
        {
          "username": "testuser",
          "authentication_method": "password",
          "sso_tokens": { "id_token": "a.b.c", "refresh_token_expires_in": 3600 },
          "signing_key_x963_base64": "\(key)",
          "reauthentication": "\(reauthentication)"
        }
        """
        return Data(text.utf8)
    }

    func testDecodesIdentityAndTokens() throws {
        let stub = try XCTUnwrap(TestStubLoginManager(json: json(key: freshX963Base64()), wrapping: nil))
        XCTAssertTrue(stub.isDeviceRegistered)
        XCTAssertTrue(stub.isUserRegistered)
        XCTAssertEqual(stub.loginUserName, "testuser")
        XCTAssertEqual(stub.authenticationMethod, .password)
        XCTAssertEqual(stub.ssoTokens?["id_token"] as? String, "a.b.c")
        XCTAssertEqual(stub.ssoTokens?["refresh_token_expires_in"] as? Int, 3600)
    }

    func testSigningKeyIsOnlyForSharedDeviceSigning() throws {
        let stub = try XCTUnwrap(TestStubLoginManager(json: json(key: freshX963Base64()), wrapping: nil))
        XCTAssertNotNil(stub.key(for: .sharedDeviceSigning))
        XCTAssertNil(stub.key(for: .userDeviceSigning))
    }

    func testExtensionDataComesFromTheWrappedManager() throws {
        let real = FakeLoginManager()
        real.extensionData = ["BaseURL": "https://idp.example.org"]
        let stub = try XCTUnwrap(TestStubLoginManager(json: json(key: freshX963Base64()), wrapping: real))
        XCTAssertEqual(stub.extensionData["BaseURL"] as? String, "https://idp.example.org")
    }

    func testBadKeyRejectsTheConfig() {
        XCTAssertNil(TestStubLoginManager(json: json(key: "bm90IGEga2V5"), wrapping: nil))
    }

    func testReauthenticationSucceeds() throws {
        let stub = try XCTUnwrap(TestStubLoginManager(json: json(key: freshX963Base64()), wrapping: nil))
        let done = expectation(description: "completion")
        stub.userNeedsReauthentication { error in
            XCTAssertNil(error)
            done.fulfill()
        }
        wait(for: [done], timeout: 1)
    }

    func testReauthenticationFails() throws {
        let stub = try XCTUnwrap(TestStubLoginManager(json: json(reauthentication: "fail", key: freshX963Base64()), wrapping: nil))
        let done = expectation(description: "completion")
        stub.userNeedsReauthentication { error in
            XCTAssertNotNil(error)
            done.fulfill()
        }
        wait(for: [done], timeout: 1)
    }

    func testReauthenticationHangNeverCompletes() throws {
        let stub = try XCTUnwrap(TestStubLoginManager(json: json(reauthentication: "hang", key: freshX963Base64()), wrapping: nil))
        let done = expectation(description: "completion")
        done.isInverted = true
        stub.userNeedsReauthentication { _ in done.fulfill() }
        wait(for: [done], timeout: 0.3)
    }

    /// The signature must verify against the public half of the key in the config.
    func testSignTokenThroughTheStubVerifies() throws {
        let key = try freshKey()
        let stub = try XCTUnwrap(TestStubLoginManager(json: json(key: x963Base64(key)), wrapping: nil))
        let vc = AuthenticationViewController(nibName: nil, bundle: nil)
        let signed = try XCTUnwrap(vc.signToken(token: "a.b.c", tokenType: "id_token", loginManager: stub, nonce: UUID(), clientId: "cid"))
        let parts = signed.split(separator: ".")
        XCTAssertEqual(parts.count, 2)

        let signature = try XCTUnwrap(base64URLDecode(String(parts[1])))
        let signedData = Data(String(parts[0]).utf8)
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        XCTAssertTrue(SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256, signedData as CFData, signature as CFData, nil))
    }

    private func base64URLDecode(_ s: String) -> Data? {
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        return Data(base64Encoded: b64)
    }
}
