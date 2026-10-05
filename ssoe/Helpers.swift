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
          //  if (loginManager.isDeviceRegistered && loginManager.isUserRegistered)
          //  {
                
                
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
        //}
        
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

        // Shows whether the initial SAML POST body reaches us at all, and in what
        // field order - that is what identified the EZproxy case. Deliberately
        // .debug, not .log: the RelayState prefix encodes the resource the user is
        // opening, and os_log debug is never persisted to disk. privacy: .public
        // because String interpolations are redacted by default, so without it you
        // get a length and nothing else. Length + first 40 bytes only.
        let bodyPrefix = String(data: httpBody.prefix(40), encoding: .utf8) ?? "<not utf8>"
        //logger.debug("webloginlog: beginAuthorization. Body length: \(httpBody.count, privacy: .public), body starts with: \(bodyPrefix, privacy: .public)")

        if let httpBodyString = String(data: httpBody, encoding: .utf8)  {
          
            
            // The starts(with:) test alone assumed the SP puts SAMLRequest first
            // in the form. EZproxy puts RelayState first, so the AuthnRequest was
            // missed, postSaml stayed false, and the /protocol/saml guard below
            // silently declined the whole login. Field order in an
            // x-www-form-urlencoded body is arbitrary, so also match SAMLRequest
            // in any later position.
            //
            // "&SAMLRequest=" rather than a bare "SAMLRequest" so we match a field
            // NAME, not a value: a literal "&" cannot occur inside a form-encoded
            // value (it must be %26), so the ampersand anchors the match to a
            // field boundary and a RelayState that happens to contain the text
            // "SAMLRequest" cannot trigger it.
            if httpBodyString.starts(with: "SAMLRequest") || httpBodyString.contains("&SAMLRequest=") {
               
                
                self.kCallbackURLString = referer
                self.postSaml = true
                self.saml = true
                
                logger.info("webloginlog: beginAuthorization. This is an initial SAML POST")
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
            // Kept at .warning on purpose: this exit used to be silent, which made
            // a declined request look identical to one the extension was never
            // offered. It cost a full debugging session.
            logger.warning("webloginlog: /protocol/saml with no SAMLRequest in the URL and postSaml == false. Not handling.")
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
    
    func getNonceFromIdp(clientRequestId: String, loginManager: (any LoginManaging)? = nil) async throws -> UUID? {
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
    
    func signToken(token: String, tokenType: String, loginManager: any LoginManaging, nonce: UUID, clientId: String) -> String? {
        guard let signingKey = loginManager.key(for: .sharedDeviceSigning) else {
            return nil
        }
        
        let now = Int(Date().timeIntervalSince1970)
        guard let signingPublicKey = SecKeyCopyPublicKey(signingKey) else {
            logger.error("webloginlog: Failed to extract public keys.")
            return nil
        }
        
        let signKeyId = computeKid(from: signingPublicKey)
        
        guard var username = loginManager.loginUserName else {
            logger.error("webloginlog: NO USERNAME SAVED!")
            return nil
        }
        
        if username.isEmpty {
            logger.log("webloginlog: the username is blank. Use the token's username.")
            let decodedToken = self.decodeJWT(token)
            username =  decodedToken?["preferred_username"] as? String ?? ""
            
        }
        
        let isSecureEnclave = loginManager.authenticationMethod == .userSecureEnclaveKey ? true : false
        let reauth_challenge = makeReauthChallenge()
        self.reauthChallenge = reauth_challenge
        
        let envelope: [String: Any] = [
            "token": token,
            "token_type" : tokenType,
            "kid": signKeyId,
            "signed_at": now,
            "username" : username,
            "nonce" : nonce.uuidString,
            "client_id": clientId,
            "secure_enclave" : isSecureEnclave,
            "reauth_challenge" : reauth_challenge
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

    /// A short, non-reversible tag for a step-up challenge, safe to log. Lets you tell
    /// two challenges apart (the rotation-desync case) without writing the secret to
    /// the unified log, where it would outlive the challenge itself.
    func challengeFingerprint(_ challenge: String) -> String {
        return String(base64URLEncode(sha256(Data(challenge.utf8))).prefix(8))
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
    


    
    
    //Block for verifying a JWT against Keycloak
    //Used for the Stepup authentication flow
    func verifyStepUpJWT(stepupToken: String,
                         localChallenge: String,
                         loginManager: (any LoginManaging)?) async -> Bool {

        
        
        guard !localChallenge.isEmpty else {
            logger.error("webloginlog: step-up verify: no local challenge armed")
            return false
        }
        guard let extensionData = loginManager?.extensionData,
              let baseURL = extensionData["BaseURL"] as? String else {
            logger.error("webloginlog: step-up verify: no BaseURL")
            return false
        }
        // jwksEndpointURL is a URL, not a String: casting it to String always yields
        // nil and silently fails every verification. loginConfiguration is also only
        // populated once a registration has saved one, hence the BaseURL fallback.
        guard let jwksURL = loginManager?.jwksEndpointURL
                ?? URL(string: baseURL + "/protocol/openid-connect/certs") else {
            logger.error("webloginlog: step-up verify: no JWKS endpoint")
            return false
        }
        let expectedIssuer = extensionData["Issuer"] as? String
        let expectedAudience = extensionData["Audience"] as? String

        // Split out of a single guard on purpose: one "malformed JWT" cannot tell you
        // whether the page sent the wrong value, an unsubstituted template placeholder,
        // or a well-formed token carrying stray whitespace.
        // Shapes only, never content: when the wrong value is passed here it is the
        // live challenge, so logging a prefix of it would put the secret in the log.
        let parts = stepupToken.components(separatedBy: ".")
        logger.debug("webloginlog: step-up verify: token length \(stepupToken.count, privacy: .public), \(parts.count, privacy: .public) part(s)")

        guard parts.count == 3 else {
            logger.error("webloginlog: step-up verify: expected 3 JWT parts, got \(parts.count, privacy: .public), total length \(stepupToken.count, privacy: .public)")
            return false
        }
        guard let headerData = base64URLDecode(parts[0]) else {
            logger.error("webloginlog: step-up verify: header is not base64url, length \(parts[0].count, privacy: .public)")
            return false
        }
        guard let payloadData = base64URLDecode(parts[1]) else {
            logger.error("webloginlog: step-up verify: payload is not base64url, length \(parts[1].count, privacy: .public)")
            return false
        }
        guard let signature = base64URLDecode(parts[2]) else {
            logger.error("webloginlog: step-up verify: signature is not base64url, length \(parts[2].count, privacy: .public)")
            return false
        }
        // The JOSE header holds only alg/kid/typ, so it is safe to log in full.
        guard let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any] else {
            logger.error("webloginlog: step-up verify: header is not JSON: \(String(data: headerData, encoding: .utf8) ?? "<not utf8>", privacy: .public)")
            return false
        }
        guard let payload = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any] else {
            logger.error("webloginlog: step-up verify: payload is not JSON")
            return false
        }
        guard let alg = header["alg"] as? String else {
            logger.error("webloginlog: step-up verify: no alg in header \(String(data: headerData, encoding: .utf8) ?? "<not utf8>", privacy: .public)")
            return false
        }

        // Pin the algorithm. Never honour alg from the token beyond this allow-list:
        // that is how alg=none and the HMAC-with-the-public-key trick get through.
        guard alg == "RS256" || alg == "ES256" else {
            logger.error("webloginlog: step-up verify: unsupported alg \(alg)")
            return false
        }

        let kid = header["kid"] as? String
        guard let jwks = await fetchJWKS(url: jwksURL, needingKid: kid) else {
            logger.error("webloginlog: step-up verify: no JWKS")
            return false
        }

        // Only keys usable for signing, and only the advertised kid when the token names one.
        let candidates = jwks.filter { jwk in
            guard ((jwk["use"] as? String) ?? "sig") == "sig" else { return false }
            if let kid = kid, let jwkKid = jwk["kid"] as? String { return jwkKid == kid }
            return true
        }
        guard !candidates.isEmpty else {
            logger.error("webloginlog: step-up verify: no JWKS key for kid \(kid ?? "nil")")
            return false
        }

        let signingInput = Data(parts[0].utf8) + Data(".".utf8) + Data(parts[1].utf8)
        guard candidates.contains(where: {
            verifyJWSSignature(alg: alg, jwk: $0, signingInput: signingInput, signature: signature)
        }) else {
            logger.error("webloginlog: step-up verify: bad signature")
            return false
        }

        guard let exp = payload["exp"] as? Double,
              Date().timeIntervalSince1970 < exp + 30 else {   // 30s clock skew
            logger.error("webloginlog: step-up verify: expired")
            return false
        }
        if let expectedIssuer, let iss = payload["iss"] as? String, iss != expectedIssuer {
            logger.error("webloginlog: step-up verify: issuer mismatch")
            return false
        }
        if let expectedAudience {
            let auds = (payload["aud"] as? [String]) ?? (payload["aud"] as? String).map { [$0] } ?? []
            guard auds.contains(expectedAudience) else {
                logger.error("webloginlog: step-up verify: audience mismatch")
                return false
            }
        }
        guard let got = payload["reauth_challenge"] as? String, got == localChallenge else {
            // Fingerprints, not values: localChallenge is the live armed secret, so it
            // must never reach the log. Truncated hashes still answer the question that
            // matters here — are these two different challenges, or is the claim absent?
            let claimed = payload["reauth_challenge"] as? String
            logger.error("webloginlog: step-up verify: challenge mismatch, claim \(claimed.map { self.challengeFingerprint($0) } ?? "<absent>", privacy: .public) vs armed \(self.challengeFingerprint(localChallenge), privacy: .public)")
            return false
        }
        return true
    }

    /// Realm JWKS, cached for the request. Refetches once when the token names a kid we
    /// do not hold, which is what a realm key rotation looks like.
    private func fetchJWKS(url: URL, needingKid kid: String?) async -> [[String: Any]]? {
        if let cached = cachedJWKS,
           Date().timeIntervalSince(cached.fetchedAt) < 300,
           kid == nil || cached.keys.contains(where: { ($0["kid"] as? String) == kid }) {
            return cached.keys
        }
        var request = URLRequest(url: url)
        request.timeoutInterval = 5     // the user is waiting on a prompt; do not hang
        guard let (data, _) = try? await URLSession.shared.data(for: request),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let keys = obj["keys"] as? [[String: Any]] else {
            logger.error("webloginlog: step-up verify: JWKS fetch failed")
            return nil
        }
        cachedJWKS = (keys, Date())
        return keys
    }

    private func verifyJWSSignature(alg: String, jwk: [String: Any],
                                    signingInput: Data, signature: Data) -> Bool {
        switch alg {
        case "ES256":
            // JWS ES256 signatures are raw r||s, not DER.
            guard let key = p256PublicKey(fromJWK: jwk), signature.count == 64,
                  let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return key.isValidSignature(sig, for: signingInput)
        case "RS256":
            guard let key = rsaPublicKey(fromJWK: jwk) else { return false }
            return SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                         signingInput as CFData, signature as CFData, nil)
        default:
            return false
        }
    }

    private func p256PublicKey(fromJWK jwk: [String: Any]) -> P256.Signing.PublicKey? {
        guard (jwk["crv"] as? String) == "P-256",
              let x = (jwk["x"] as? String).flatMap(base64URLDecode),
              let y = (jwk["y"] as? String).flatMap(base64URLDecode),
              x.count == 32, y.count == 32 else { return nil }
        return try? P256.Signing.PublicKey(x963Representation: Data([0x04]) + x + y)
    }

    /// CryptoKit has no RSA, so rebuild a SecKey from the JWK's modulus and exponent
    /// via a PKCS#1 RSAPublicKey DER blob.
    private func rsaPublicKey(fromJWK jwk: [String: Any]) -> SecKey? {
        guard let n = (jwk["n"] as? String).flatMap(base64URLDecode),
              let e = (jwk["e"] as? String).flatMap(base64URLDecode) else { return nil }
        let body = derInteger(n) + derInteger(e)
        let der = Data([0x30]) + derLength(body.count) + body
        return SecKeyCreateWithData(der as CFData,
                                    [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                     kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, nil)
    }

    private func derLength(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var len = n, bytes: [UInt8] = []
        while len > 0 { bytes.insert(UInt8(len & 0xff), at: 0); len >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    private func derInteger(_ raw: Data) -> Data {
        var b = Array(raw)
        while b.count > 1 && b[0] == 0x00 { b.removeFirst() }
        if let f = b.first, f & 0x80 != 0 { b.insert(0x00, at: 0) }  // keep it positive
        return Data([0x02]) + derLength(b.count) + Data(b)
    }

    func base64URLDecode(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+")
                 .replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t.append("=") }
        return Data(base64Encoded: t)
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

    func makeReauthChallenge() -> String {
        return base64URLEncode(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
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


