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
//  RegistrationStateTests.swift
//  ssoeTests
//
//  Unit tests for RegistrationState (ssoe/RegistrationState.swift).
//
//  RegistrationState is a process-wide singleton. Each test fully sets the
//  fields it inspects before asserting, so ordering between tests does not
//  matter for the properties under test.
//

import XCTest
import AuthenticationServices

final class RegistrationStateTests: XCTestCase {

    func testClearResetsCompletionAndInProgressFlag() {
        let state = RegistrationState.shared
        state.isRegistrationInProgress = true
        state.registrationCompletion = { _ in }

        state.clear()

        XCTAssertFalse(state.isRegistrationInProgress)
        XCTAssertNil(state.registrationCompletion)
    }

    func testClearDeliberatelyPreservesPkceVerifier() {
        // clear() intentionally does NOT reset pkceVerifier (the token
        // exchange still needs the verifier after registration completes).
        // This test documents that current contract.
        let state = RegistrationState.shared
        state.pkceVerifier = "verifier-should-survive-clear"

        state.clear()

        XCTAssertEqual(state.pkceVerifier, "verifier-should-survive-clear")
    }

    func testClearDeliberatelyPreservesTokenAndUsername() {
        // clear() also leaves accessToken / idpUsername / registrationType /
        // loginManager untouched (the loginManager reset is commented out in
        // the implementation). Guard against silent behavioural changes.
        let state = RegistrationState.shared
        state.accessToken = "an-access-token"
        state.idpUsername = "someuser"
        state.registrationType = "user"

        state.clear()

        XCTAssertEqual(state.accessToken, "an-access-token")
        XCTAssertEqual(state.idpUsername, "someuser")
        XCTAssertEqual(state.registrationType, "user")
    }

    func testSharedIsASingleton() {
        XCTAssertTrue(RegistrationState.shared === RegistrationState.shared)
    }

    func testMutationsAreVisibleThroughSharedInstance() {
        RegistrationState.shared.pkceVerifier = "abc123"
        XCTAssertEqual(RegistrationState.shared.pkceVerifier, "abc123")
    }
}
