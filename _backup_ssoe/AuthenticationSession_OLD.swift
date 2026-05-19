//
//  AuthenticationSession.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 18/05/2026.
//

import AuthenticationServices


extension AuthenticationViewController {

    

    func startLogin(authURL: URL, token: String) {
        
        let callbackScheme = "weblogin-sso"

        
        authSession = ASWebAuthenticationSession(
            url: authURL,
            callbackURLScheme: callbackScheme
        ) { callbackURL, error in

            if let url = callbackURL {
                let queryItems = URLComponents(string: url.absoluteString)?.queryItems
                let code = queryItems?.first(where: { $0.name == "code" })?.value
                
                Task {
                    @MainActor in
                    do { 
                        let token = try await self.exchangeCodeForToken(code: code!)
                        let access_token = self.decodeJWT(token.access_token)
                        if let idpUsername = access_token?["preferred_username"] as? String {
                            RegistrationState.shared.idpUsername = idpUsername
                            logger.log("webloginlog: Will now call the \(RegistrationState.shared.registrationType!) registration")
                            
                            
                            
                            if RegistrationState.shared.registrationType == "device" {
                                self.registerDevice(accessToken: token.access_token, userName: idpUsername)
                                return
                                
                                
                                
                            }else {
                                logger.log("webloginlog: Starting user registration")
                                self.registerUser(accessToken: token.access_token)
                                return
                                
                            }
                            self.isMainViewHidden = true
                            RegistrationState.shared.isRegistrationInProgress = false
                            
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
        
        if !token.isEmpty {
            authSession?.additionalHeaderFields = ["Platform-SSO-Authorization": "Bearer \(token)"]
        }
        logger.log("webloginlog: Starting Authentication web session")
        // Flag is already set in idpLogin before this is called
        authSession?.presentationContextProvider = self
        authSession?.prefersEphemeralWebBrowserSession = true
        authSession?.start()
    }
}

extension AuthenticationViewController: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(
        for session: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        view.window!
    }
}
