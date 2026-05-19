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

import Cocoa
import AuthenticationServices
import CryptoKit
import OSLog

class RegistrationHandler: NSObject {
    weak var viewController: AuthenticationViewController?
    var authSession: ASWebAuthenticationSession?
    var mdmConfig: (baseURL: String, issuer: String, clientID: String, audience: String)?

    override init() {
        super.init()
        loadMDMConfig()
    }

    func beginDeviceRegistration(
        loginManager: ASAuthorizationProviderExtensionLoginManager,
        options: ASAuthorizationProviderExtensionRequestOptions = [],
        completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void
    ) {
        logger.debug("webloginlog: beginDeviceRegistration")

        RegistrationState.shared.loginManager = loginManager
        RegistrationState.shared.registrationCompletion = completion
        RegistrationState.shared.isRegistrationInProgress = true
        RegistrationState.shared.registrationType = "device"

        guard let viewController = viewController else {
            logger.error("webloginlog: No view controller available")
            completion(.failed)
            return
        }

        viewController.isDeviceRegistrationFlow = true
        viewController.isMainViewHidden = false

        if let win = viewController.view.window {
            win.makeKeyAndOrderFront(nil)
            win.setContentSize(NSMakeSize(10, 10))
        }

        viewController.isMainViewHidden = false
        viewController.view.alphaValue = 1.0
        viewController.view.window?.isOpaque = true
        viewController.view.needsLayout = true
        viewController.view.layoutSubtreeIfNeeded()
        viewController.view.displayIfNeeded()

        if loginManager.registrationToken == nil {
            logger.log("Device registration started using User Login.")
            loginManager.presentRegistrationViewController { result in
                self.idpLogin(isSetupAssistant: options.contains(.setupAssistant), loginManager: loginManager)
            }
        } else {
            logger.log("webloginlog: Device Registration started using Registration Token.")
            registerDevice(accessToken: "", userName: "", loginManager: loginManager)
        }
    }

    func beginUserRegistration(
        loginManager: ASAuthorizationProviderExtensionLoginManager,
        userName: String?,
        method authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod,
        options: ASAuthorizationProviderExtensionRequestOptions = [],
        completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void
    ) {
        if !options.contains(.userInteractionEnabled) {
            completion(.userInterfaceRequired)
            return
        }

        logger.debug("webloginlog: is device registered? \(loginManager.isDeviceRegistered)")
        logger.log("webloginlog: Starting user registration")

        RegistrationState.shared.loginManager = loginManager
        RegistrationState.shared.registrationCompletion = completion
        RegistrationState.shared.isRegistrationInProgress = true
        RegistrationState.shared.registrationType = "user"
        let token = RegistrationState.shared.accessToken

        if token != nil {
            logger.log("webloginlog: user has token. Proceeding to user registration")
            registerUser(accessToken: token!, loginManager: loginManager)
        } else {
            guard let viewController = viewController else {
                logger.error("webloginlog: No view controller available")
                completion(.failed)
                return
            }

            if let win = viewController.view.window {
                win.makeKeyAndOrderFront(nil)
                win.setContentSize(NSMakeSize(10, 10))
            }

            loginManager.presentRegistrationViewController { error in
                if let error = error {
                    logger.error("webloginlog: \(error)")
                    completion(.failed)
                    return
                }

                self.idpLogin(isSetupAssistant: options.contains(.setupAssistant), loginManager: loginManager)
            }
        }
    }

    func idpLogin(isSetupAssistant: Bool, loginManager: ASAuthorizationProviderExtensionLoginManager) {
        logger.debug("webloginlog: Starting IdP login")

        var refreshToken: String?
        if isSetupAssistant {
            if let ssoTokens = loginManager.ssoTokens {
                refreshToken = ssoTokens[AnyHashable("refresh_token")] as? String
            }
        }

        RegistrationState.shared.accessToken = nil
        guard let baseURL = self.mdmConfig?.baseURL,
              let clientID = self.mdmConfig?.clientID else {
            logger.error("Missing MDM baseURL or clientID")
            return
        }

        let verifier = randomString(length: 64)
        let challenge = sha256Base64URL(verifier)
        RegistrationState.shared.pkceVerifier = verifier

        // Set this BEFORE starting the session to avoid race condition
        RegistrationState.shared.isRegistrationInProgress = true

        let state = UUID().uuidString
        var components = URLComponents(string: "\(baseURL)/protocol/openid-connect/auth")!

        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: "weblogin-sso://idp-login-redirect"),
            URLQueryItem(name: "scope", value: "openid profile"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "prompt", value: "login")
        ]

        guard let authURL = components.url else {
            logger.error("Failed to construct Keycloak auth URL")
            return
        }

        logger.debug("webloginlog: Presenting login page: \(authURL.absoluteString)")

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            self.startLogin(authURL: authURL, refreshToken: refreshToken ?? "", loginManager: loginManager)
        }
    }

    func startLogin(authURL: URL, refreshToken: String, loginManager: ASAuthorizationProviderExtensionLoginManager) {
        let callbackScheme = "weblogin-sso"

        authSession = ASWebAuthenticationSession(
            url: authURL,
            callbackURLScheme: callbackScheme
        ) { callbackURL, error in
            if let url = callbackURL {
                let queryItems = URLComponents(string: url.absoluteString)?.queryItems
                let code = queryItems?.first(where: { $0.name == "code" })?.value

                Task { @MainActor in
                    do {
                        let token = try await self.exchangeCodeForToken(code: code!)
                        let access_token = decodeJWT(token.access_token)
                        if let idpUsername = access_token?["preferred_username"] as? String {
                            RegistrationState.shared.idpUsername = idpUsername
                            logger.log("webloginlog: Will now call the \(RegistrationState.shared.registrationType!) registration")

                            if RegistrationState.shared.registrationType == "device" {
                                self.registerDevice(accessToken: token.access_token, userName: idpUsername, loginManager: loginManager)
                                return
                            } else {
                                logger.log("webloginlog: Starting user registration")
                                self.registerUser(accessToken: token.access_token, loginManager: loginManager)
                                return
                            }
                        }
                    }
                }
            } else if let error = error {
                logger.log("webloginlog: There was an error: \(error.localizedDescription)")
                RegistrationState.shared.isRegistrationInProgress = false
                RegistrationState.shared.registrationCompletion?(.failed)
                return
            }
        }

        if !refreshToken.isEmpty {
            authSession?.additionalHeaderFields = ["Platform-SSO-Authorization": "Bearer \(refreshToken)"]
        }

        logger.log("webloginlog: Starting Authentication web session")
        authSession?.presentationContextProvider = self
        authSession?.prefersEphemeralWebBrowserSession = true
        authSession?.start()
    }

    func registerDevice(accessToken: String, userName: String, loginManager: ASAuthorizationProviderExtensionLoginManager) {
        guard let completion = RegistrationState.shared.registrationCompletion else {
            logger.error("webloginlog: No completion handler saved for device registration. Aborting.")
            return
        }

        if loginManager.registrationToken == nil {
            RegistrationState.shared.accessToken = accessToken
            RegistrationState.shared.idpUsername = userName
        }

        let clientRequestId = UUID().uuidString
        do {
            loginManager.resetDeviceKeys()
        } catch {
            logger.error("webloginlog: Failed to reset device keys: \(error)")
        }

        guard let signingKey = loginManager.key(for: .sharedDeviceSigning),
              let encryptionKey = loginManager.key(for: .sharedDeviceEncryption) else {
            logger.error("webloginlog: Failed to get device keys.")
            completion(.failed)
            return
        }

        guard let signingPublicKey = SecKeyCopyPublicKey(signingKey),
              let encryptionPublicKey = SecKeyCopyPublicKey(encryptionKey) else {
            logger.error("webloginlog: Failed to extract public keys.")
            completion(.failed)
            return
        }

        let signingKeyData = SecKeyCopyExternalRepresentation(signingPublicKey, nil)! as Data
        let encryptionKeyData = SecKeyCopyExternalRepresentation(encryptionPublicKey, nil)! as Data

        let signingKeyB64 = signingKeyData.base64EncodedString(options: [])
        let encryptionKeyB64 = encryptionKeyData.base64EncodedString(options: [])

        let signKeyId = computeKid(from: signingPublicKey)
        let encKeyId = computeKid(from: encryptionPublicKey)

        guard let baseURL = mdmConfig?.baseURL else {
            logger.error("webloginlog: No baseURL found")
            completion(.failed)
            return
        }

        do {
            let config = configuration()
            try config.setCustomLoginRequestBodyClaims(["signKeyId": signKeyId, "encKeyId": encKeyId])
            try loginManager.saveLoginConfiguration(config)
        } catch {
            logger.error("webloginlog: Failed to save the configuration \(error)")
        }

        var nonce: UUID?
        Task {
            do {
                let nonceValue = try await getNonceFromIdp(clientRequestId: clientRequestId)
                logger.debug("webloginlog; Got nonce: \(nonceValue!.uuidString)")
                nonce = nonceValue
            } catch {
                logger.error("webloginlog: Error fetching nonce: \(error)")
                completion(.failed)
                return
            }

            guard let baseURL = mdmConfig?.baseURL else {
                logger.error("webloginlog: No baseURL found on SSO Extension profile from MDM.")
                completion(.failed)
                return
            }

            guard let url = URL(string: baseURL + "/psso/enroll") else {
                completion(.failed)
                return
            }

            let nonceData = nonce!.uuidString.lowercased().data(using: .utf8)!
            let nonceHash = SHA256.hash(data: nonceData)
            let nonceHashData = Data(nonceHash)
            let attestCertificate = try await loginManager.attestKey(ofType: .sharedDeviceSigning, clientDataHash: nonceHashData)

            let attestationB64 = attestCertificate.compactMap { cert -> String? in
                guard let data = SecCertificateCopyData(cert) as Data? else { return nil }
                return data.base64EncodedString(options: [])
            }

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue(clientRequestId, forHTTPHeaderField: "client-request-id")

            var registrationMethod: String
            switch loginManager.authenticationMethod {
            case .password:
                registrationMethod = "PASSWORD"
            case .userSecureEnclaveKey:
                registrationMethod = "SECURE_ENCLAVE"
            default:
                registrationMethod = "SECURE_ENCLAVE"
            }

            var params = [
                "DeviceSigningKey": signingKeyB64,
                "DeviceEncryptionKey": encryptionKeyB64,
                "SignKeyID": signKeyId,
                "EncKeyID": encKeyId,
                "nonce": nonce!.uuidString.lowercased(),
                "attestation": attestationB64,
                "registrationMethod": registrationMethod
            ] as [String: Any]

            if loginManager.registrationToken != nil {
                logger.log("webloginlog: using Registration Token for device registration.")
                params["registrationToken"] = loginManager.registrationToken
            } else {
                logger.log("webloginlog: using Access Token for device registration.")
                params["accessToken"] = accessToken
            }

            let jsonBody = try JSONSerialization.data(withJSONObject: params, options: [])
            request.httpBody = jsonBody

            let urlString = url.absoluteString
            logger.debug("webloginlog: Sending registration to \(urlString)")

            URLSession.shared.dataTask(with: request) { data, response, error in
                if let httpResponse = response as? HTTPURLResponse,
                   (200...299).contains(httpResponse.statusCode) || httpResponse.statusCode == 409 {
                    logger.log("webloginlog: Device successfully registered.")
                    completion(.success)
                    RegistrationState.shared.clear()
                    return
                } else {
                    let responseHTTP = response as? HTTPURLResponse
                    let code = responseHTTP?.statusCode ?? 0
                    logger.error("webloginlog: Error was \(code)")
                    logger.error("webloginlog: Device Registration failed: \(error?.localizedDescription ?? "unknown")")
                    completion(.failed)
                    RegistrationState.shared.clear()
                    return
                }
            }.resume()
        }
    }

    func registerUser(accessToken: String, loginManager: ASAuthorizationProviderExtensionLoginManager) {
        logger.log("webloginlog: Begin Register User")

        guard let completion = RegistrationState.shared.registrationCompletion else {
            logger.error("webloginlog: No Login Manager or Registration Completion")
            return
        }

        guard let userName = RegistrationState.shared.idpUsername else {
            logger.error("webloginlog: No username found.")
            completion(.failed)
            return
        }

        logger.log("webloginlog: User being registered is: \(userName)")

        let config = ASAuthorizationProviderExtensionUserLoginConfiguration(loginUserName: userName)
        config.loginUserName = userName

        do {
            try loginManager.saveUserLoginConfiguration(config)
        } catch {
            logger.error("webloginlog: Failed to save the configuration \(error).")
            completion(.failed)
        }

        if loginManager.authenticationMethod == .password {
            let audience = loginManager.loginConfiguration?.audience
            logger.log("webloginlog: The audience in user registration is: \(audience as NSObject?)")
            let _ = loginManager.key(for: .userDeviceSigning)
            completion(.success)
            return
        }

        loginManager.resetUserSecureEnclaveKey()
        guard let userKey = loginManager.key(for: .userSecureEnclaveKey) else {
            logger.error("webloginlog: No user key found.")
            completion(.failed)
            return
        }

        guard let userPublicKey = SecKeyCopyPublicKey(userKey) else {
            logger.error("webloginlog: Can't export the public key for the user.")
            completion(.failed)
            return
        }

        let userKeyId = computeKid(from: userPublicKey)
        let userKeyData = SecKeyCopyExternalRepresentation(userPublicKey, nil)! as Data
        let userKeyB64 = userKeyData.base64EncodedString(options: [])

        logger.debug("webloginlog: username registered from idp is \(userName)")

        var nonce: UUID?
        let clientRequestId = UUID().uuidString
        Task {
            do {
                let nonceValue = try await getNonceFromIdp(clientRequestId: clientRequestId)
                logger.debug("webloginlog; Got nonce: \(nonceValue!.uuidString)")
                nonce = nonceValue
            } catch {
                logger.debug("webloginlog: Error fetching nonce: \(error)")
                completion(.failed)
                return
            }

            let nonceData = nonce!.uuidString.lowercased().data(using: .utf8)!
            let nonceHash = SHA256.hash(data: nonceData)
            let nonceHashData = Data(nonceHash)

            let keyType = loginManager.authenticationMethod == .password ? ASAuthorizationProviderExtensionKeyType.userDeviceSigning : ASAuthorizationProviderExtensionKeyType.userSecureEnclaveKey

            let attestCertificate = try await loginManager.attestKey(ofType: keyType, clientDataHash: nonceHashData)

            let attestationB64 = attestCertificate.compactMap { cert -> String? in
                guard let data = SecCertificateCopyData(cert) as Data? else { return nil }
                return data.base64EncodedString(options: [])
            }

            logger.debug("webloginlog: user attestation: \(attestationB64)")
            guard let baseURL = mdmConfig?.baseURL else {
                logger.error("webloginlog: No baseURL found on SSO Extension profile from MDM.")
                completion(.failed)
                return
            }

            guard let url = URL(string: baseURL + "/psso/userenroll") else {
                completion(.failed)
                return
            }

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue(clientRequestId, forHTTPHeaderField: "client-request-id")

            let params = [
                "userKey": userKeyB64,
                "userKeyId": userKeyId,
                "nonce": nonce!.uuidString.lowercased(),
                "attestation": attestationB64,
                "accessToken": accessToken
            ] as [String: Any]

            let jsonBody = try JSONSerialization.data(withJSONObject: params, options: [])
            request.httpBody = jsonBody

            let urlString = url.absoluteString
            logger.debug("webloginlog: Sending user registration to \(urlString)")

            URLSession.shared.dataTask(with: request) { data, response, error in
                if let httpResponse = response as? HTTPURLResponse,
                   (200...299).contains(httpResponse.statusCode) || httpResponse.statusCode == 409 {
                    completion(.success)
                    RegistrationState.shared.clear()
                    return
                } else {
                    let responseHTTP = response as? HTTPURLResponse
                    let code = responseHTTP?.statusCode ?? 0
                    logger.error("webloginlog: Error was \(code)")
                    logger.error("webloginlog: User Registration failed: \(error?.localizedDescription ?? "unknown")")
                    completion(.failed)
                    RegistrationState.shared.clear()
                    return
                }
            }.resume()
        }
    }

    func configuration() -> ASAuthorizationProviderExtensionLoginConfiguration {
        logger.debug("webloginlog: getting configuration")
        let domain = Bundle.main.bundleIdentifier ?? "no.uio.webloginSSO.ssoe"

        let clientID = CFPreferencesCopyAppValue("ClientID" as CFString, domain as CFString) as? String ?? "fallback-client"
        let baseURL = CFPreferencesCopyAppValue("BaseURL" as CFString, domain as CFString) as? String ?? "fallback-baseURL"
        let issuer = CFPreferencesCopyAppValue("Issuer" as CFString, domain as CFString) as? String ?? "fallback-issuer"
        let audience = CFPreferencesCopyAppValue("Audience" as CFString, domain as CFString) as? String ?? "fallback-audience"

        let tokenEndpointURL = URL(string: baseURL + "/psso/token")!
        let jwksEndpointURL = URL(string: baseURL + "/protocol/openid-connect/certs")!

        let config = ASAuthorizationProviderExtensionLoginConfiguration(
            clientID: clientID,
            issuer: issuer,
            tokenEndpointURL: tokenEndpointURL,
            jwksEndpointURL: jwksEndpointURL,
            audience: audience
        )

        if let nonceEndpointURL = URL(string: baseURL + "/psso/nonce") {
            config.nonceEndpointURL = nonceEndpointURL
        }

        config.refreshEndpointURL = tokenEndpointURL
        config.keyEndpointURL = tokenEndpointURL
        config.nonceResponseKeypath = "nonce"
        config.groupResponseClaimName = "groups"
        config.audience = audience

        return config
    }

    func registrationDidComplete() {
        logger.debug("webloginlog: Registration Did complete done.")
    }

    func supportedGrantTypes() -> ASAuthorizationProviderExtensionSupportedGrantTypes {
        return [.password, .jwtBearer]
    }

    func protocolVersion() -> ASAuthorizationProviderExtensionPlatformSSOProtocolVersion {
        return .version2_0
    }

    // MARK: - Helper methods

    private func loadMDMConfig() {
        let domain = Bundle.main.bundleIdentifier ?? "no.uio.WebloginSSO.ssoe"

        guard let baseURL = stringFromManagedPreferences(forKey: "BaseURL", inDomain: domain) else {
            logger.error("webloginlog: BaseURL not found in MDM config")
            return
        }

        guard let issuer = stringFromManagedPreferences(forKey: "Issuer", inDomain: domain) else {
            logger.error("webloginlog: Issuer not found")
            return
        }

        guard let clientID = stringFromManagedPreferences(forKey: "ClientID", inDomain: domain) else {
            logger.error("webloginlog: ClientID not found")
            return
        }

        guard let audience = stringFromManagedPreferences(forKey: "Audience", inDomain: domain) else {
            logger.error("webloginlog: Audience not found")
            return
        }

        logger.debug("webloginlog: Loaded MDM config → BaseURL: \(baseURL), ClientID: \(clientID)")

        self.mdmConfig = (baseURL, issuer, clientID, audience)
    }

    private func stringFromManagedPreferences(forKey key: String, inDomain domain: String) -> String? {
        guard let value = CFPreferencesCopyAppValue(key as CFString, domain as CFString) else {
            return nil
        }
        return value as? String
    }

    private func randomString(length: Int) -> String {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        return String((0..<length).compactMap { _ in characters.randomElement() })
    }

    private func sha256Base64URL(_ input: String) -> String {
        let data = Data(input.utf8)
        let hash = SHA256.hash(data: data)
        let base64 = Data(hash).base64EncodedString()
        return base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func exchangeCodeForToken(code: String) async throws -> TokenResponse {
        guard let baseURL = self.mdmConfig?.baseURL else { throw URLError(.badURL) }
        guard let clientId = self.mdmConfig?.clientID else { throw URLError(.badURL) }
        let url = URL(string: "\(baseURL)/protocol/openid-connect/token")!
        var request = URLRequest(url: url)

        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let verifier = RegistrationState.shared.pkceVerifier
        let body = "grant_type=authorization_code&code=\(code)&redirect_uri=weblogin-sso://idp-login-redirect&client_id=\(clientId)&code_verifier=\(verifier)"
        request.httpBody = body.data(using: .utf8)

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    private func getNonceFromIdp(clientRequestId: String) async throws -> UUID? {
        let config = configuration()
        let nonceEndpointURL = config.nonceEndpointURL
        var nonceRequest = URLRequest(url: nonceEndpointURL)
        nonceRequest.httpMethod = "POST"
        nonceRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        nonceRequest.setValue(clientRequestId, forHTTPHeaderField: "client-request-id")

        let formData = "grant_type=srv_challenge"
        nonceRequest.httpBody = formData.data(using: .utf8)
        do {
            let (data, _) = try await URLSession.shared.data(for: nonceRequest)
            let nonceJSON = try JSONDecoder().decode(Nonce.self, from: data)
            logger.debug("webloginlog: Nonce fetched from IdP: \(nonceJSON.nonce)")
            return nonceJSON.nonce
        } catch {
            logger.error("webloginlog: Error fetching nonce: \(error)")
            return nil
        }
    }

    struct TokenResponse: Codable {
        let access_token: String
        let refresh_token: String
        let id_token: String
        let expires_in: Int
    }

    struct Nonce: Decodable {
        let nonce: UUID
    }
}

extension RegistrationHandler: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        viewController!.view.window!
    }
}
