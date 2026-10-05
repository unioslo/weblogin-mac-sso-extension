/* Copyright 2025 University of Oslo, Norway
 # This file is part of the Weblogin SSO Extension codebase.
 # Licensed under the GNU GPL v2 or later. See LICENSE.
*/

//
//  RegistrationCompletionRegressionTests.swift
//  ssoeTests
//
//  Checks that RegistrationState.clear() drops the stored registration
//  completion, so a late call after clearing cannot reach it.
//

import XCTest

final class RegistrationCompletionRegressionTests: XCTestCase {

    /// RegistrationState.clear() must drop the completion so a later stray call is a no-op.
    func testClearDropsCompletionReference() {
        RegistrationState.shared.registrationCompletion = { _ in }
        RegistrationState.shared.isRegistrationInProgress = true
        RegistrationState.shared.clear()
        XCTAssertNil(RegistrationState.shared.registrationCompletion)
        XCTAssertFalse(RegistrationState.shared.isRegistrationInProgress)
    }
}
