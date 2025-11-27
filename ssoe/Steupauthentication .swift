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
//  Steupauthentication .swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 26/11/2025.
//

import WebKit
import LocalAuthentication



extension AuthenticationViewController: WKScriptMessageHandler {
    
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {

        logger.log("webloginlog: Got a JS message.")
        guard message.name == "pssoStepUp" else { return }
        guard let body = message.body as? [String: Any] else { return }

        if let type = body["type"] as? String, type == "getSignedToken" {
            
            handleStepUpRequest{
                error in
                    if let error = error {
                        print("Reauthentication failed: \(error)")
                        return
                    }
                DispatchQueue.main.async {
                      
                    let tokens = self.loginManager?.ssoTokens
                    if let loginManager = self.loginManager, let value = tokens?[AnyHashable("refresh_token")] as? String {
                    if let refreshToken = tokens?["refresh_token"]{
                        let signedToken = self.signToken(token: refreshToken as! String, loginManager: loginManager)
                        self.signedRefreshToken = signedToken
                        self.sendSignedTokenToJS(self.signedRefreshToken ?? "none");
                        
                        
                    }
                    
                        
                    }
                }
                
        }
    }

    func handleStepUpRequest(completion: @escaping ((any Error)?) -> Void) {
        // Perform the platform SSO reauthentication logic...
        // Then produce your new signed token.

        Task {
            let ctx = LAContext()
 
            let localizedReason = String(localized: "authenticate you")
            
            ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: localizedReason) { (success, error) in
                logger.log("webloginlog: User asked for reauthentication. Success: \(success)")
                
                if success != true {
                    logger.log("webloginlog: User didn't approve login. Returning.")
                   // self.authorizationRequest?.cancel()
                    self.sendSignedTokenToJS( "none");
                    return
                    
                }
                
                self.loginManager?.userNeedsReauthentication{ error in
                    
                    completion(error)
                }
                    
                }
            
            }
            
            
        }
        
    }

    func sendSignedTokenToJS(_ signedToken: String) {
        // Escape quotes and backslashes for safe JS embedding
        
        let js = "pssoSigned('\(signedToken)');"

        DispatchQueue.main.async {
            self.webView.evaluateJavaScript(js) { _, error in
                if let error = error {
                    logger.error("webloginlog: Error calling pssoSigned: \(error)")
                }
            }
        }
    }

}
