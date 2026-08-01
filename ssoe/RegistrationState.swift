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
//  RegistrationState.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 12/11/2025.
//

import AuthenticationServices

final class RegistrationState {
    static let shared = RegistrationState()

    // Shared across extension process launches. The in-memory singleton is not
    // reliable here: beginAuthorization can be serviced by a freshly relaunched
    // extension process that never saw the flag set during registration, so we
    // back it with the App Group so any process instance can read it.
    private static let sharedDefaults = UserDefaults(suiteName: "group.no.uio.weblogin")
    private static let registrationInProgressKey = "isRegistrationInProgress"

    // set by beginDeviceRegistration
    var loginManager: ASAuthorizationProviderExtensionLoginManager?
    var registrationCompletion: ((ASAuthorizationProviderExtensionRegistrationResult) -> Void)?
    var isRegistrationInProgress: Bool {
        get { Self.sharedDefaults?.bool(forKey: Self.registrationInProgressKey) ?? false }
        set { Self.sharedDefaults?.set(newValue, forKey: Self.registrationInProgressKey) }
    }
    var pkceVerifier = ""
    var accessToken: String?
    var idpUsername: String?
    var registrationType: String?
    var pictureURL: String?
    
    // small helper to clear
    func clear() {
       // loginManager = nil
        registrationCompletion = nil
        isRegistrationInProgress = false
        
    }
}
