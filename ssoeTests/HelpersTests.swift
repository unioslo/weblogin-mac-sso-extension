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
//  HelpersTests.swift
//  ssoeTests
//
//  Unit tests for the pure helper functions declared in ssoe/Helpers.swift.
//
//  These tests are compiled into the same module as the code under test
//  (the ssoe sources are members of the ssoeTests target), so the internal
//  instance methods on AuthenticationViewController are callable directly —
//  no @testable import is possible for an app-extension target.
//
//  The exercised helpers are pure: they do not touch outlets, network,
//  the keychain/Secure Enclave, biometric hardware, or the login manager.
//  We instantiate AuthenticationViewController via its designated
//  initializer WITHOUT ever accessing `.view`, so no view loading occurs.
//

import XCTest
import Foundation
import CryptoKit
import Security
import AuthenticationServices

final class HelpersTests: XCTestCase {

    // Subject under test. Created with the designated initializer so that
    // `viewDidLoad` is never triggered (we never touch `.view`).
    private var vc: AuthenticationViewController!

    override func setUp() {
        super.setUp()
        vc = AuthenticationViewController(nibName: nil, bundle: nil)
    }

    override func tearDown() {
        vc = nil
        super.tearDown()
    }

    // MARK: - htmlEscape

    func testHtmlEscapeEscapesAllFiveSensitiveCharacters() {
        XCTAssertEqual(vc.htmlEscape("&<>\""), "&amp;&lt;&gt;&quot;")
    }

    func testHtmlEscapeEscapesAmpersandFirstSoItDoesNotDoubleEscape() {
        // If `<` were escaped before `&`, the resulting `&lt;` ampersand would
        // be re-escaped. Verify the ampersand in the output is NOT doubled.
        let out = vc.htmlEscape("<a href=\"x\">T & J</a>")
        XCTAssertEqual(out, "&lt;a href=&quot;x&quot;&gt;T &amp; J&lt;/a&gt;")
        XCTAssertFalse(out.contains("&amp;lt;"), "ampersand was double-escaped")
    }

    func testHtmlEscapeLeavesPlainTextUntouched() {
        XCTAssertEqual(vc.htmlEscape("hello world 123"), "hello world 123")
    }

    // MARK: - base64URLEncode

    func testBase64URLEncodeStripsPadding() {
        let data = Data("Hello, World!".utf8)
        XCTAssertEqual(vc.base64URLEncode(data), "SGVsbG8sIFdvcmxkIQ")
    }

    func testBase64URLEncodeReplacesPlusAndSlash() {
        // These bytes produce "+/+/" in standard base64.
        let data = Data([0xfb, 0xff, 0xbf])
        XCTAssertEqual(data.base64EncodedString(), "+/+/")
        XCTAssertEqual(vc.base64URLEncode(data), "-_-_")
    }

    func testBase64URLEncodeEmptyData() {
        XCTAssertEqual(vc.base64URLEncode(Data()), "")
    }

    // MARK: - sha256

    func testSha256MatchesKnownVector() {
        // NIST test vector for SHA-256("abc").
        let digest = vc.sha256(Data("abc".utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(digest.count, 32)
    }

    func testSha256MatchesCryptoKit() {
        let data = Data("some arbitrary payload".utf8)
        XCTAssertEqual(vc.sha256(data), Data(SHA256.hash(data: data)))
    }

    // MARK: - decodeJWT

    func testDecodeJWTReturnsClaims() {
        // Payload: {"sub":"alice","admin":true,"n":42}
        let payload = Data("{\"sub\":\"alice\",\"admin\":true,\"n\":42}".utf8)
        let payloadB64 = vc.base64URLEncode(payload)
        let jwt = "eyJhbGciOiJIUzI1NiJ9." + payloadB64 + ".signaturepart"

        let claims = vc.decodeJWT(jwt)
        XCTAssertNotNil(claims)
        XCTAssertEqual(claims?["sub"] as? String, "alice")
        XCTAssertEqual(claims?["admin"] as? Bool, true)
        XCTAssertEqual(claims?["n"] as? Int, 42)
    }

    func testDecodeJWTHandlesBase64URLPayloadNeedingPadding() {
        // A payload whose base64url form has stripped padding and uses '-'/'_'.
        let payload = Data("{\"data\":\"\u{00fb}\u{00ff}\"}".utf8)
        let jwt = "header." + vc.base64URLEncode(payload) + ".sig"
        XCTAssertNotNil(vc.decodeJWT(jwt))
    }

    func testDecodeJWTReturnsNilForFewerThanTwoSegments() {
        XCTAssertNil(vc.decodeJWT("onlyonesegment"))
    }

    func testDecodeJWTReturnsNilForNonBase64Payload() {
        // "!!!" is not valid base64 even after url->std substitution.
        XCTAssertNil(vc.decodeJWT("header.!!!.sig"))
    }

    // MARK: - exportPublicKeyDER / computeKid (real EC key pair)

    /// Generates a fresh, in-memory (non-Secure-Enclave) P-256 key pair.
    private func makeECPublicKey() throws -> SecKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error),
              let pub = SecKeyCopyPublicKey(priv) else {
            throw XCTSkip("Could not create EC key pair: \(String(describing: error))")
        }
        return pub
    }

    func testExportPublicKeyDERForP256IsUncompressedPoint() throws {
        let pub = try makeECPublicKey()
        let der = vc.exportPublicKeyDER(pub)
        // SecKeyCopyExternalRepresentation for an EC public key returns the
        // uncompressed point 0x04 || X || Y, which is 65 bytes for P-256.
        XCTAssertEqual(der.count, 65)
        XCTAssertEqual(der.first, 0x04)
    }

    func testComputeKidIsBase64OfSha256OfDER() throws {
        let pub = try makeECPublicKey()
        let der = vc.exportPublicKeyDER(pub)
        let expected = Data(SHA256.hash(data: der)).base64EncodedString()

        let kid = vc.computeKid(from: pub)
        XCTAssertEqual(kid, expected)
        // 32-byte SHA-256 digest, standard base64 -> 44 characters.
        XCTAssertEqual(kid.count, 44)
    }

    func testComputeKidIsDeterministic() throws {
        let pub = try makeECPublicKey()
        XCTAssertEqual(vc.computeKid(from: pub), vc.computeKid(from: pub))
    }

    func testComputeKidDiffersBetweenKeys() throws {
        let a = try makeECPublicKey()
        let b = try makeECPublicKey()
        XCTAssertNotEqual(vc.computeKid(from: a), vc.computeKid(from: b))
    }

    // MARK: - biometricPolicyFromExtensionData

    func testBiometricPolicyNilWhenNoBasePolicyRequested() {
        XCTAssertNil(vc.biometricPolicyFromExtensionData([:]))
        // Modifiers alone (without a base policy) must not synthesize a policy.
        XCTAssertNil(vc.biometricPolicyFromExtensionData([
            "ReuseUnlock": true,
            "PasswordFallback": true,
        ]))
    }

    func testBiometricPolicyTouchIDOrWatchAny() throws {
        let policy = try XCTUnwrap(vc.biometricPolicyFromExtensionData([
            "UseTouchIDOrWatchAny": true
        ]))
        XCTAssertTrue(policy.contains(.touchIDOrWatchAny))
        XCTAssertFalse(policy.contains(.reuseDuringUnlock))
        XCTAssertFalse(policy.contains(.passwordFallback))
    }

    func testBiometricPolicyCurrentSetWithModifiers() throws {
        let policy = try XCTUnwrap(vc.biometricPolicyFromExtensionData([
            "UseTouchIDOrWatchCurrentSet": true,
            "ReuseUnlock": true,
            "PasswordFallback": true,
        ]))
        XCTAssertTrue(policy.contains(.touchIDOrWatchCurrentSet))
        XCTAssertTrue(policy.contains(.reuseDuringUnlock))
        XCTAssertTrue(policy.contains(.passwordFallback))
    }

    func testBiometricPolicyCurrentSetTakesPrecedenceOverAny() throws {
        // Both base flags set: "current set" is checked first and wins.
        let policy = try XCTUnwrap(vc.biometricPolicyFromExtensionData([
            "UseTouchIDOrWatchCurrentSet": true,
            "UseTouchIDOrWatchAny": true,
        ]))
        XCTAssertTrue(policy.contains(.touchIDOrWatchCurrentSet))
    }

    func testBiometricPolicyIgnoresFalseAndNonBoolValues() {
        XCTAssertNil(vc.biometricPolicyFromExtensionData([
            "UseTouchIDOrWatchAny": false,
            "UseTouchIDOrWatchCurrentSet": "yes",   // wrong type, ignored
        ]))
    }
}
