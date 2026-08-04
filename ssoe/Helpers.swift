//
//  Helpers.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 26/11/2025.
//

import Foundation
import CryptoKit
import AuthenticationServices
import LocalAuthentication



extension AuthenticationViewController {
    
   
    struct TokenResponse: Codable {
        let access_token: String
        let refresh_token: String
        let id_token: String
        let expires_in: Int
    }
    
   
    
    
    struct Nonce: Decodable {
        let nonce: UUID
    }
    
    func insertPssoTokens(request: ASAuthorizationProviderExtensionAuthorizationRequest, tokens: [AnyHashable: Any]?){
        let clientRequestId = UUID().uuidString
        Task {

        if let tokens {
            for token in tokens {
                let name = token.key as? String
                    let value = token.value as? String? ?? "nil"
            //   logger.log("webloginlog: \(name ?? "nil"): \(value!)")
                }
        }
     
        if let loginManager = loginManager {
            if (loginManager.isDeviceRegistered && loginManager.isUserRegistered)
            {
                
                
                var tokenType = "";
                if let value = tokens?[AnyHashable("refresh_token_expires_in")] as? Int {
                    tokenType = "refresh_token"
                    
                }else {
                    tokenType = "id_token"
                }
                
                if let value = tokens?[AnyHashable(tokenType)] as? String {
                    if let tokenToSign = loginManager.ssoTokens?[tokenType]{

                        guard let nonce = try? await self.getNonceFromIdp(clientRequestId: clientRequestId) else {
                                logger.error("webloginlog: Failed to fetch nonce")
                                self.authorizationRequest?.complete(error: ASAuthorizationError(.failed))
                                return
                            }
                        
                        let signedToken = signToken(token: tokenToSign as! String, tokenType: tokenType, loginManager: loginManager, nonce: nonce, clientId: clientRequestId)
                        self.signedTokenToSend = signedToken
                    }
                }
            }
        }
        
        if let headers = authorizationRequest?.httpHeaders {
            // Look for Referer, custom hints, etc.
            if let foundReferer = headers["Referer"] as? String {
                self.referer  = foundReferer
                // This often identifies the SP origin for SAML requests
                logger.debug("webloginlog: Referer header: \(self.referer)")
            }
        }
        
        url=request.url
        
        if let authURL = request.url.baseURL?.absoluteString {
            logger.debug("webloginlog: beginAuthorization. The request url starts with: \(authURL)")
        }
        
        var newRequest = URLRequest(url: request.url)
        let httpBody = request.httpBody
        
        if let httpBodyString = String(data: httpBody, encoding: .utf8)  {
          
            
            if httpBodyString.starts(with: "SAMLRequest"){
               
                
                self.kCallbackURLString = referer
                self.postSaml = true
                self.saml = true
                
                logger.debug("webloginlog: beginAuthorization. This is an initial SAML POST")
                /*
                Task{
                    await handleInitialSamlPost(request: request, bodyString: httpBodyString)

                }*/
                
                
                newRequest.httpMethod = "POST"
                newRequest.httpBody = request.httpBody
                newRequest.allHTTPHeaderFields = request.httpHeaders
               
                 
                
            }
       

        }
        
        // return if it is a saml endpoint but not a saml request:
        if request.url.absoluteString.starts(with:"\(baseURL)/protocol/saml" ) == true && request.url.absoluteString.contains("SAMLRequest") == false && self.postSaml == false {
            authorizationRequest?.doNotHandle()
            return
        }
        
                
        request.presentAuthorizationViewController(completion: { (success, error) in
            if error != nil {
                request.complete(error: error!)
            }
        })
        
      
            if let components = URLComponents(url: url!, resolvingAgainstBaseURL: false),
               let redirectParam = components.queryItems?.first(where: { $0.name == "redirect_uri" })?.value {
                self.kCallbackURLString = redirectParam
                logger.debug("webloginlog: beginAuthorization. Callback URL set to \(self.kCallbackURLString)")
                
                
                
            } else {
                // fallback: maybe the SP uses a fixed URL
                self.kCallbackURLString = referer
                self.saml = true
                logger.warning("webloginlog: No redirect_uri query param found, using referrer \(self.kCallbackURLString)")
            }
            if let url = url {
                var request = URLRequest(url: url)
                //let cookies = getCookies()
                if (self.postSaml){
                    request = newRequest
                }
                
                if let signedTokenToSend {
                    logger.debug("webloginlog: Signed token being sent to Keycloak")
                    request.setValue("Bearer \(signedTokenToSend)", forHTTPHeaderField: "Platform-SSO-Authorization")
                    
                }
                request.httpShouldHandleCookies = true
                await MainActor.run {
                    self.webView.load(request)
                }
            }
        }
        
    }
    
    func getNonceFromIdp(clientRequestId: String, loginManager: ASAuthorizationProviderExtensionLoginManager? = nil) async throws -> UUID? {
        // Use provided loginManager or fall back to self.loginManager
        guard let manager = loginManager ?? self.loginManager else {
            logger.error("webloginlog: No loginManager available for getNonceFromIdp")
            throw URLError(.badURL)
        }

        let config = configuration(loginManager: manager)
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
        }
        catch {
            logger.error("webloginlog: Error fetching nonce: \(error)")
            return nil
        }
    }
    
    func signToken(token: String, tokenType: String, loginManager: ASAuthorizationProviderExtensionLoginManager, nonce: UUID, clientId: String) -> String? {
        guard let signingKey = loginManager.key(for: .sharedDeviceSigning) else {
            return nil
        }
        
        let now = Int(Date().timeIntervalSince1970)
        guard let signingPublicKey = SecKeyCopyPublicKey(signingKey) else {
            logger.error("webloginlog: Failed to extract public keys.")
            return nil
        }
        
        let signKeyId = computeKid(from: signingPublicKey)
        
        guard let username = loginManager.userLoginConfiguration?.loginUserName else {
            logger.error("webloginlog: NO USERNAME SAVED!")
            return nil
        }
        
        let isSecureEnclave = loginManager.authenticationMethod == .userSecureEnclaveKey ? true : false
        
        let envelope: [String: Any] = [
            "token": token,
            "token_type" : tokenType,
            "kid": signKeyId,
            "signed_at": now,
            "username" : username,
            "nonce" : nonce.uuidString,
            "client_id": clientId,
            "secure_enclave" : isSecureEnclave
        ]
        do {
            let jsonData = try? JSONSerialization.data(withJSONObject: envelope, options: [])
            if let jsonData = jsonData {
                
                
                let envB64 =  base64URLEncode(jsonData)
                let dataToSign = Data(envB64.utf8)
                
                do {
                      let signature = SecKeyCreateSignature(signingKey, .ecdsaSignatureMessageX962SHA256, dataToSign as CFData, nil)
                        
                        let sigData = signature as? Data
                        if let sigData{
                            let sigB64  = base64URLEncode(sigData)
                            return "\(envB64).\(sigB64)"
                    }
                }
                
            }
            
        }
    return nil
    }
    
    func exchangeCodeForToken(code: String) async throws -> TokenResponse {
        // Get fresh ExtensionData from loginManager
        guard let loginManager = RegistrationState.shared.loginManager else {
            logger.error("webloginlog: No loginManager available for exchangeCodeForToken")
            throw URLError(.badURL)
        }

        let extensionData = loginManager.extensionData
        guard let baseURL = extensionData["BaseURL"] as? String else {
            logger.error("webloginlog: BaseURL not found in ExtensionData during exchangeCodeForToken")
            throw URLError(.badURL)
        }

        guard let clientId = extensionData["ClientID"] as? String else {
            logger.error("webloginlog: ClientID not found in ExtensionData during exchangeCodeForToken")
            throw URLError(.badURL)
        }

        let url = URL(string: "\(baseURL)/protocol/openid-connect/token")!
        var request = URLRequest(url: url)
        
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let verifier = RegistrationState.shared.pkceVerifier
        let body = "grant_type=authorization_code&code=\(code)&redirect_uri=weblogin-sso://idp-login-redirect&client_id=\(clientId)&code_verifier=\(verifier)"
        request.httpBody = body.data(using: .utf8)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        do {
            let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
            
            
            if let json = json {
                for (key, value) in json {
                   // logger.debug("webloginlog: \(key): \(String(describing: value))")
                }
            } else {
                logger.error("webloginlog: Could not parse token response as dictionary")
            }
            
        } catch {
            logger.error("webloginlog: Failed to decode JSON: \(error.localizedDescription)")
            if let rawString = String(data: data, encoding: .utf8) {
                logger.error("webloginlog: Raw response string: \(rawString)")
            }
        }
        
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }
    
    
    
    
    func htmlEscape(_ s: String) -> String {
        return s
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
    
    func base64URLEncode(_ data: Data) -> String {
        var s = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return s
    }
    
    func computeKid(from publicKey: SecKey) -> String {
        let der = exportPublicKeyDER(publicKey)
        let hash = sha256(der)
        return hash.base64EncodedString()
    }
    
    func exportPublicKeyDER(_ key: SecKey) -> Data {
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            fatalError("webloginlog: Could not export public key: \(String(describing: error))")
        }
        return der
    }
    
    func sha256(_ data: Data) -> Data {
        let hash = SHA256.hash(data: data)
        return Data(hash)
    }
    
    func decodeJWT(_ jwt: String) -> [String: Any]? {
        let segments = jwt.split(separator: ".")
        guard segments.count >= 2 else { return nil }
        
        let payloadSegment = segments[1]
        
        var payload = payloadSegment
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        // Pad base64 if needed
        while payload.count % 4 != 0 {
            payload.append("=")
        }
        
        guard let data = Data(base64Encoded: payload) else { return nil }
        
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
    
    func showProcessingOverlay() {
        overlayView.isHidden = false
        spinner.startAnimation(nil)
    }
    func hideProcessingOverlay() {
        overlayView.isHidden = true
        spinner.stopAnimation(nil)
    }
    

    
    func stringFromManagedPreferences(forKey key: String, inDomain domain: String) -> String? {
        guard let value = CFPreferencesCopyAppValue(key as CFString, domain as CFString) else {
            return nil
        }
        return value as? String
    }
    
    func loadMDMConfig(loginManager: ASAuthorizationProviderExtensionLoginManager) {
        
        

        let extensionData = loginManager.extensionData
        
        guard let baseURL = extensionData["BaseURL"] as? String else {
            logger.error("webloginlog: BaseURL not found in MDM config")
            return
        }
        
        guard let issuer = extensionData["Issuer"] as? String else {
            logger.error("webloginlog: Issuer not found")
            return
        }
        
        guard let clientID = extensionData["ClientID"] as? String else {
            logger.error("webloginlog: ClientID not found")
            return
        }
        
        guard let audience = extensionData["Audience"] as? String else {
            logger.error("webloginlog: Audience not found")
            return
        }
        
        logger.debug("webloginlog: Loaded MDM config → BaseURL: \(baseURL), ClientID: \(clientID)")
        
        self.mdmConfig = (baseURL, issuer, clientID, audience)
    }
    
    
    func deviceSupportsBiometrics() -> Bool {
        let context = LAContext()
        var error: NSError?

        // This returns true only if biometrics are enrolled AND available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
    error: &error) {
            return true
        }

        // If false, check why - hardware might exist but not be enrolled
        if let error = error {
            switch error.code {
            case LAError.biometryNotEnrolled.rawValue:
                // Hardware exists, but user hasn't enrolled biometrics
                return true
            case LAError.biometryNotAvailable.rawValue:
                // No biometric hardware (e.g., desktop Mac without Touch ID)
                return false
            default:
                return false
            }
        }

        return false
    }

    func biometricPolicyFromExtensionData(_ extensionData: [AnyHashable: Any]) -> ASAuthorizationProviderExtensionLoginConfiguration.UserSecureEnclaveKeyBiometricPolicy? {
        // Determine base policy (mutually exclusive - first one wins)
        var policy: ASAuthorizationProviderExtensionLoginConfiguration.UserSecureEnclaveKeyBiometricPolicy?

        if extensionData["UseTouchIDOrWatchCurrentSet"] as? Bool == true {
            policy = .touchIDOrWatchCurrentSet
        } else if extensionData["UseTouchIDOrWatchAny"] as? Bool == true {
            policy = .touchIDOrWatchAny
        }

        // Add modifiers if we have a base policy
        if var policy = policy {
            if extensionData["ReuseUnlock"] as? Bool == true {
                policy.insert(.reuseDuringUnlock)
            }

            if extensionData["PasswordFallback"] as? Bool == true {
                policy.insert(.passwordFallback)
            }

            return policy
        }

        return nil
    }

    func updateConfiguration(loginManager: ASAuthorizationProviderExtensionLoginManager) {
        guard let currentConfig = loginManager.loginConfiguration else {
            logger.warning("webloginlog: No existing configuration to update")
            return
        }

        let extensionData = loginManager.extensionData ?? [:]
        let desiredPolicy = biometricPolicyFromExtensionData(extensionData)

        // Check if device supports biometrics
        let canUseBiometrics = deviceSupportsBiometrics()

        // Determine what the policy should be
        let targetPolicy: ASAuthorizationProviderExtensionLoginConfiguration.UserSecureEnclaveKeyBiometricPolicy?
        if let policy = desiredPolicy, canUseBiometrics {
            targetPolicy = policy
        } else {
            targetPolicy = []
        }

        // Compare with current policy
        let currentPolicy = currentConfig.userSecureEnclaveKeyBiometricPolicy

        if currentPolicy != targetPolicy {
            logger.debug("webloginlog: Biometric policy has changed, updating configuration")

    
            
            if let targetPolicy = targetPolicy, let newConfig = loginManager.loginConfiguration {
                newConfig.userSecureEnclaveKeyBiometricPolicy = targetPolicy
            
                do {
                    try loginManager.saveLoginConfiguration(newConfig)
                    loginManager.deviceRegistrationsNeedsRepair()
                    logger.log("webloginlog: Configuration updated successfully")
                } catch {
                    logger.log("webloginlog: Failed to update configuration: \(error)")
                }
            }

           
        } else {
            logger.debug("webloginlog: Biometric policy unchanged, no update needed")
        }
    }

    

    
    
}

extension AuthenticationViewController: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        self.view.window!
    }
    
        
        
        

        
        
        func startLogin(authURL: URL, refreshToken: String, loginManager: ASAuthorizationProviderExtensionLoginManager) {
                let callbackScheme = "weblogin-sso"

                authSession = ASWebAuthenticationSession(
                    url: authURL,
                    callbackURLScheme: callbackScheme
                ) { callbackURL, error in
                    if let url = callbackURL {
                        let queryItems = URLComponents(string: url.absoluteString)?.queryItems
                        guard let code = queryItems?.first(where: { $0.name == "code" })?.value else {
                            logger.error("webloginlog: No code in the callback URL")
                            RegistrationState.shared.isRegistrationInProgress = false
                            RegistrationState.shared.registrationCompletion?(.failed)
                            return
                        }

                        Task { @MainActor in
                            do {
                                let token = try await self.exchangeCodeForToken(code: code)
                                let access_token = self.decodeJWT(token.access_token)
                                if let idpUsername = access_token?["preferred_username"] as? String {
                                    RegistrationState.shared.idpUsername = idpUsername
                                    logger.log("webloginlog: Will now call the \(RegistrationState.shared.registrationType!) registration")

                                    if RegistrationState.shared.registrationType == "device" {
                                        self.registerDevice(accessToken: token.access_token, userName: idpUsername)
                                        RegistrationState.shared.isRegistrationInProgress = false

                                        return
                                    } else {
                                        logger.log("webloginlog: Starting user registration")
                                        RegistrationState.shared.isRegistrationInProgress = false

                                        self.registerUser(accessToken: token.access_token)
                                        return
                                    }
                                } else {
                                    logger.error("webloginlog: No preferred_username in access token")
                                    RegistrationState.shared.isRegistrationInProgress = false
                                    RegistrationState.shared.registrationCompletion?(.failed)
                                    return
                                }
                            } catch {
                                logger.error("webloginlog: Failed to exchange code for token: \(error)")
                                RegistrationState.shared.isRegistrationInProgress = false
                                RegistrationState.shared.registrationCompletion?(.failed)
                                return
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
    }

 
extension NSImage {

    func jpegData(compressionQuality: CGFloat = 0.9) -> Data? {
        guard
            let tiffData = tiffRepresentation,
            let bitmap = NSBitmapImageRep(data: tiffData)
        else {
            return nil
        }

        return bitmap.representation(
            using: .jpeg,
            properties: [
                .compressionFactor: compressionQuality
            ]
        )
    }
}


