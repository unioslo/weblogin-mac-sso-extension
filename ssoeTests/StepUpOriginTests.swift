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
//  StepUpOriginTests.swift
//  ssoeTests
//
//  Unit tests for the origin check that gates the pssoStepUp script
//  message bridge (ssoe/StepUpAuthentication.swift). The check is a pure
//  comparison of scheme, host and port against the configured BaseURL,
//  so it can be exercised without a web view.
//

import XCTest
import Foundation

final class StepUpOriginTests: XCTestCase {

    private var vc: AuthenticationViewController!

    override func setUp() {
        super.setUp()
        vc = AuthenticationViewController(nibName: nil, bundle: nil)
        vc.baseURL = "https://idp.example.org/realms/test"
    }

    override func tearDown() {
        vc = nil
        super.tearDown()
    }

    // MARK: - Matching origins

    func testExactSchemeAndHostWithNoPortMatches() {
        XCTAssertTrue(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: nil))
    }

    func testExplicitDefaultPortMatchesImplicitDefaultPort() {
        XCTAssertTrue(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: 443))
    }

    func testZeroPortMeansDefaultPort() {
        // WKSecurityOrigin reports 0 for the scheme's default port.
        XCTAssertTrue(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: 0))
    }

    func testSchemeAndHostCompareCaseInsensitively() {
        XCTAssertTrue(vc.isConfiguredIdPOrigin(scheme: "HTTPS", host: "IDP.Example.ORG", port: nil))
    }

    func testNonDefaultPortMatchesWhenConfigured() {
        vc.baseURL = "https://idp.example.org:8444/realms/test"
        XCTAssertTrue(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: 8444))
    }

    // MARK: - Rejected origins

    func testDifferentHostIsRejected() {
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: "evil.example.org", port: nil))
    }

    func testHostPrefixIsRejected() {
        // A string-prefix comparison would accept this. An origin comparison must not.
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org.evil.net", port: nil))
    }

    func testDifferentSchemeIsRejected() {
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "http", host: "idp.example.org", port: nil))
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "http", host: "idp.example.org", port: 443))
    }

    func testDifferentPortIsRejected() {
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: 8443))
    }

    func testDefaultPortIsRejectedWhenNonDefaultPortIsConfigured() {
        vc.baseURL = "https://idp.example.org:8444/realms/test"
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: nil))
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: 443))
    }

    func testMissingSchemeOrHostIsRejected() {
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: nil, host: "idp.example.org", port: nil))
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: nil, port: nil))
    }

    func testEmptyOrInvalidBaseURLRejectsEverything() {
        vc.baseURL = ""
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: nil))
        vc.baseURL = "not a url"
        XCTAssertFalse(vc.isConfiguredIdPOrigin(scheme: "https", host: "idp.example.org", port: nil))
    }

    // MARK: - URL variant

    func testURLOnConfiguredOriginMatchesRegardlessOfPath() {
        XCTAssertTrue(vc.isConfiguredIdPURL(URL(string: "https://idp.example.org/realms/test/login-actions/x?y=1")))
        XCTAssertTrue(vc.isConfiguredIdPURL(URL(string: "https://idp.example.org/")))
    }

    func testURLOnOtherOriginIsRejected() {
        XCTAssertFalse(vc.isConfiguredIdPURL(URL(string: "https://evil.example.org/realms/test")))
        XCTAssertFalse(vc.isConfiguredIdPURL(URL(string: "http://idp.example.org/realms/test")))
        XCTAssertFalse(vc.isConfiguredIdPURL(URL(string: "https://idp.example.org:8443/realms/test")))
    }

    func testNilURLIsRejected() {
        XCTAssertFalse(vc.isConfiguredIdPURL(nil))
    }
}
