//
//  Helpers.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 26/11/2025.
//

import Foundation
import CryptoKit
import AuthenticationServices



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
    
    func getNonceFromIdp(clientRequestId: String) async throws -> UUID? {
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
        }
        catch {
            logger.error("webloginlog: Error fetching nonce: \(error)")
            return nil
        }
    }
    
    func signToken(token: String, tokenType: String, loginManager: ASAuthorizationProviderExtensionLoginManager) -> String? {
        guard let signingKey = loginManager.key(for: .sharedDeviceSigning) else {
            return nil
        }
        let now = Int(Date().timeIntervalSince1970)
        
        guard let userKey = loginManager.key(for: .userSecureEnclaveKey) else {
            return nil
        }
        
        
        guard let signingPublicKey = SecKeyCopyPublicKey(signingKey) else {
            logger.error("webloginlog: Failed to extract public keys.")
            return nil
        }
        
        
        guard let userPublicKey = SecKeyCopyPublicKey(userKey) else {
            logger.error("webloginlog: Failed to extract public keys.")
            return nil
        }
        
        let signKeyId = computeKid(from: signingPublicKey)
        let userKid = computeKid(from: userPublicKey)
        
        guard let username = loginManager.userLoginConfiguration?.loginUserName else {
            logger.error("webloginlog: NO USERNAME SAVED!")
            return nil
        }
        
        let envelope: [String: Any] = [
            "token": token,
            "token_type" : tokenType,
            "kid": signKeyId,
            "signed_at": now,
            "username" : username,
            "user_kid" : userKid
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
        guard let baseURL = self.mdmConfig?.baseURL else { throw URLError(.badURL) }
        guard let clientId = self.mdmConfig?.clientID else { throw URLError(.badURL)}
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
    
    func loadMDMConfig() {
        
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
    
    
}
