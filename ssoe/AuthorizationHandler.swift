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
import WebKit
import OSLog
import CryptoKit

class AuthorizationHandler: NSObject {
    weak var viewController: AuthenticationViewController?
    var mdmConfig: (baseURL: String, issuer: String, clientID: String, audience: String)?

    var url: URL?
    var authorizationRequest: ASAuthorizationProviderExtensionAuthorizationRequest?
    var kCallbackURLString = ""
    var saml = false
    var referer = ""
    var is_post: Bool = false
    var post_done: Bool = false
    var postHeaders: [String: String] = [:]
    private var firstResponseChecked = false
    private var showedInteractiveLogin = false
    var isRequiredAction: Bool = false
    var postSaml: Bool = false
    var signedTokenToSend: String?
    var loginManager: ASAuthorizationProviderExtensionLoginManager?

    override init() {
        super.init()
        loadMDMConfig()
    }

    func beginAuthorization(with request: ASAuthorizationProviderExtensionAuthorizationRequest) {
        guard let viewController = viewController else { return }

        viewController.destroyRegistrationWebView()
        self.authorizationRequest = request
        self.firstResponseChecked = false
        self.showedInteractiveLogin = false

        logger.log("webloginlog: Begin Authorization")
        logger.log("webloginlog: Registration in progress: \(RegistrationState.shared.isRegistrationInProgress)")

        // Check if this is a registration flow by URL pattern
        let requestURL = request.url.absoluteString
        if requestURL.contains("redirect_uri=weblogin-sso://idp-login-redirect") ||
           requestURL.contains("redirect_uri=weblogin-sso%3A%2F%2Fidp-login-redirect") {
            authorizationRequest?.doNotHandle()
            logger.log("webloginlog: Detected registration flow (by redirect_uri), not handling")
            return
        }

        if RegistrationState.shared.isRegistrationInProgress == true {
            authorizationRequest?.doNotHandle()
            logger.log("webloginlog: Registration in progress and handled by the Authentication web session")
            return
        }

        viewController.webView.configuration.userContentController.add(viewController, name: "pssoStepUp")

        let sharedDefaults = UserDefaults(suiteName: "group.no.uio.weblogin")
        let disableSSO = sharedDefaults?.bool(forKey: "disable_sso") ?? false
        let deviceRegistered = request.loginManager?.isDeviceRegistered ?? false && request.loginManager?.isUserRegistered ?? false
        let userRegistered = request.loginManager?.isUserRegistered ?? false && request.loginManager?.isUserRegistered ?? false
        logger.log("webloginlog: is sso disabled? \(disableSSO)")
        logger.log("webloginlog: is device and user registered? \(userRegistered && deviceRegistered)")

        if disableSSO || !deviceRegistered || !userRegistered {
            logger.log("webloginlog: SSO is disabled or the device is not registered. Won't display browser.")
            viewController.webView.configuration.userContentController.removeAllScriptMessageHandlers()
            authorizationRequest?.doNotHandle()
            return
        }

        guard let mdmConfig else {
            logger.error("webloginlog: No MDM config, aborting")
            authorizationRequest?.complete(error: ASAuthorizationError(.canceled))
            return
        }

        let baseURL = URL(string: mdmConfig.baseURL)!
        let authorizationURLs = ["\(baseURL)/protocol/openid-connect/auth", "\(baseURL)/protocol/saml"]

        var startAuthorization = false

        for authorizationURL in authorizationURLs {
            logger.info("webloginlog: checking authorization url: \(authorizationURL)")
            if request.url.absoluteURL.absoluteString.starts(with: authorizationURL) {
                logger.info("webloginlog: beginning authorization url: \(authorizationURL)")
                startAuthorization = true
                break
            }
        }

        if !startAuthorization {
            viewController.webView.configuration.userContentController.removeAllScriptMessageHandlers()
            authorizationRequest?.doNotHandle()
            return
        }

        let loginManager = request.loginManager
        self.loginManager = loginManager

        if let loginManager = loginManager {
            viewController.updateConfiguration(loginManager: loginManager)
        }

        let tokens = loginManager?.ssoTokens

        if let tokens {
            logger.log("webloginlog: There are SSO Tokens. Using them.")
            insertPssoTokens(request: request, tokens: tokens)
        } else {
            loginManager?.userNeedsReauthentication { error in
                if let error {
                    logger.error("webloginlog: Error: \(error.localizedDescription)")
                    viewController.webView.configuration.userContentController.removeAllScriptMessageHandlers()
                    self.authorizationRequest?.doNotHandle()
                } else {
                    let tokens = self.loginManager?.ssoTokens
                    logger.log("webloginlog: Got tokens.")
                    self.insertPssoTokens(request: request, tokens: tokens)
                }
            }
        }
    }

    func insertPssoTokens(request: ASAuthorizationProviderExtensionAuthorizationRequest, tokens: [AnyHashable: Any]?) {
        guard let viewController = viewController else { return }
        let clientRequestId = UUID().uuidString

        Task {
            if let tokens {
                for token in tokens {
                    let name = token.key as? String
                    let value = token.value as? String? ?? "nil"
                }
            }

            if let loginManager = loginManager {
                if loginManager.isDeviceRegistered && loginManager.isUserRegistered {
                    var tokenType = ""
                    if let _ = tokens?[AnyHashable("refresh_token_expires_in")] as? Int {
                        tokenType = "refresh_token"
                    } else {
                        tokenType = "id_token"
                    }

                    if let _ = tokens?[AnyHashable(tokenType)] as? String {
                        if let tokenToSign = loginManager.ssoTokens?[tokenType] {
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
                if let foundReferer = headers["Referer"] as? String {
                    self.referer = foundReferer
                    logger.debug("webloginlog: Referer header: \(self.referer)")
                }
            }

            url = request.url

            if let authURL = request.url.baseURL?.absoluteString {
                logger.debug("webloginlog: beginAuthorization. The request url starts with: \(authURL)")
            }

            var newRequest = URLRequest(url: request.url)
            let httpBody = request.httpBody

            if let httpBodyString = String(data: httpBody, encoding: .utf8) {
                if httpBodyString.starts(with: "SAMLRequest") {
                    self.kCallbackURLString = referer
                    self.postSaml = true
                    self.saml = true

                    logger.debug("webloginlog: beginAuthorization. This is an initial SAML POST")

                    newRequest.httpMethod = "POST"
                    newRequest.httpBody = request.httpBody
                    newRequest.allHTTPHeaderFields = request.httpHeaders
                }
            }

            // return if it is a saml endpoint but not a saml request:
            guard let baseURL = mdmConfig?.baseURL else { return }
            if request.url.absoluteString.starts(with: "\(baseURL)/protocol/saml") == true && request.url.absoluteString.contains("SAMLRequest") == false && self.postSaml == false {
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
                self.kCallbackURLString = referer
                self.saml = true
                logger.warning("webloginlog: No redirect_uri query param found, using referrer \(self.kCallbackURLString)")
            }

            if let url = url {
                var request = URLRequest(url: url)
                if self.postSaml {
                    request = newRequest
                }

                if let signedTokenToSend {
                    logger.debug("webloginlog: Signed token being sent to Keycloak")
                    request.setValue("Bearer \(signedTokenToSend)", forHTTPHeaderField: "Platform-SSO-Authorization")
                }
                request.httpShouldHandleCookies = true
                await MainActor.run {
                    viewController.webView.load(request)
                }
            }
        }
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

    func getNonceFromIdp(clientRequestId: String) async throws -> UUID? {
        guard let baseURL = mdmConfig?.baseURL else { throw URLError(.badURL) }
        let nonceEndpointURL = URL(string: baseURL + "/psso/nonce")!
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

    func signToken(token: String, tokenType: String, loginManager: ASAuthorizationProviderExtensionLoginManager, nonce: UUID, clientId: String) -> String? {
        guard let signingKey = loginManager.key(for: .sharedDeviceSigning) else {
            logger.error("webloginlog: No signing key available")
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
            "token_type": tokenType,
            "kid": signKeyId,
            "signed_at": now,
            "username": username,
            "nonce": nonce.uuidString,
            "client_id": clientId,
            "secure_enclave": isSecureEnclave
        ]

        // Log envelope contents (without the actual token value)
        logger.debug("webloginlog: Token envelope - type: \(tokenType), kid: \(signKeyId.prefix(20))..., username: \(username), client_id: \(clientId), secure_enclave: \(isSecureEnclave)")

        guard let jsonData = try? JSONSerialization.data(withJSONObject: envelope, options: []) else {
            logger.error("webloginlog: Failed to serialize envelope to JSON")
            return nil
        }

        let envB64 = base64URLEncode(jsonData)
        let dataToSign = Data(envB64.utf8)

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(signingKey, .ecdsaSignatureMessageX962SHA256, dataToSign as CFData, &error) else {
            logger.error("webloginlog: Failed to create signature: \(String(describing: error))")
            return nil
        }

        guard let sigData = signature as Data? else {
            logger.error("webloginlog: Failed to convert signature to Data")
            return nil
        }

        let sigB64 = base64URLEncode(sigData)
        logger.debug("webloginlog: Successfully created signature")
        return "\(envB64).\(sigB64)"
    }

    private func base64URLEncode(_ data: Data) -> String {
        var s = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return s
    }

    struct Nonce: Decodable {
        let nonce: UUID
    }
}
