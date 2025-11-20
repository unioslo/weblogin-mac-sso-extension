//
//  RegistrationState.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 12/11/2025.
//

import AuthenticationServices

final class RegistrationState {
    static let shared = RegistrationState()

    // set by beginDeviceRegistration
    var loginManager: ASAuthorizationProviderExtensionLoginManager?
    var registrationCompletion: ((ASAuthorizationProviderExtensionRegistrationResult) -> Void)?
    var isRegistrationInProgress: Bool = false
    var pkceVerifier = ""
    var accessToken: String?
    var idpUsername: String?
    var registrationType: String?
    // small helper to clear
    func clear() {
        loginManager = nil
        registrationCompletion = nil
        isRegistrationInProgress = false
        
    }
}
