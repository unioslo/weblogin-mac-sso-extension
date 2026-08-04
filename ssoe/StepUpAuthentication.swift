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
        
        guard message.name == "pssoStepUp" else { return }
        logger.log("webloginlog: Got a JS message.")
        
        guard let body = message.body as? [String: Any] else { return }
        
        if let type = body["type"] as? String, type == "getSignedToken" {
            
            
            
            
            handleStepUpRequest{
                error in
                if let error = error {
                    logger.log("webloginlog: Reauthentication failed: \(error)")
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                        self.sendSignedTokenToJS( "none");
                    }
                    return
                }
                
                
                Task { @MainActor in
                    logger.log("webloginlog: Sending signed token to the IdP via javascript")
                    
                    let tokens = self.loginManager?.ssoTokens
                    var tokenType = "";
                    if let value = tokens?[AnyHashable("refresh_token_expires_in")] as? Int {
                        tokenType = "refresh_token"
                        
                    }else {
                        tokenType = "id_token"
                    }
                    let clientId = UUID().uuidString
                  
                        guard let nonce = try? await self.getNonceFromIdp(clientRequestId: clientId) else {
                            logger.error("webloginlog: Failed to fetch nonce")
                            return
                            
                        }
                        
                        if let loginManager = self.loginManager, let value = tokens?[AnyHashable(tokenType)] as? String {
                            if let token = tokens?[tokenType]{
                                let signedToken = self.signToken(token: token as! String, tokenType: tokenType, loginManager: loginManager, nonce: nonce, clientId: clientId)
                                self.signedTokenToSend = signedToken
                                self.sendSignedTokenToJS(self.signedTokenToSend ?? "none");
                                
                                
                            }
                            
                            
                        }
                    }
                    
                
            }
        }
        
        func handleStepUpRequest(completion: @escaping ((any Error)?) -> Void) {
            // Perform the platform SSO reauthentication logic...
            // Then produce your new signed token.
            
            // Make sure UI changes happen on main thread
            
            // This is unnecessary as Keycloak will not send a JS message
            // when the authentication method is Password. Nevertheless we keep this here
            // so that we can revaluate this in the future
            
            let forceIdpReauthentication = loginManager?.extensionData["ForceIDPReauthentication"] as? Bool ?? false
            
            if forceIdpReauthentication == true {
                if loginManager?.authenticationMethod == .password {
                    self.sendSignedTokenToJS("none")
                    return
                    
                }
                
            }
            
            let forceLocalReauthentication = loginManager?.extensionData["ForceLocalReauthentication"] as? Bool ?? false
            
            dumpActivationState("label")
            self.view.isHidden = true
            self.view.window?.makeKeyAndOrderFront(nil)
            self.view.window?.setContentSize(NSMakeSize(10,10))
            
            self.view.window?.isOpaque = false
            self.view.window?.backgroundColor = .clear
            // Make entire view controller contents transparent
            self.view.layer?.backgroundColor = NSColor.clear.cgColor
            self.view.alphaValue = 0.0
            self.view.wantsLayer = true
            self.isMainViewHidden = false
            
            // self.cancelButton.isHidden = false
            self.view.needsLayout = true
            self.webView.isHidden = false
            // Force redraw
            self.view.displayIfNeeded()
            self.view.layoutSubtreeIfNeeded()
            
            
            Task {@MainActor in 
                view.window?.makeKeyAndOrderFront(self)
                if forceLocalReauthentication == false {
                    logger.log("webloginlog: Reauthentication required")
                    self.loginManager?.userNeedsReauthentication{ error in
                        
                        logger.log("webloginlog: Error in reauthentication: \(error?.localizedDescription ?? "no error description")")
                        if error != nil {
                            logger.log("webloginlog: Error with userNeedsReauthentication")
                            DispatchQueue.main.async {
                                self.sendSignedTokenToJS("none")
                                completion(error)
                                    //return
                            }
                            return
                        }
                        logger.info( "webloginlog: User successfully reauthenticated. Proceeding with login.")
                        completion(nil)
                    }
                    return
                }
                else {
                    
                    let ctx = LAContext()
                    let localizedReason = String(localized: "authenticate you")
                    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: localizedReason) {   (success, error) in
                        logger.log("webloginlog: User asked for reauthentication. Success: \(success)")
                        
                        if success != true {
                            logger.log("webloginlog: User didn't approve login. Returning.")
                            // self.authorizationRequest?.cancel()
                            
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                                
                                self.sendSignedTokenToJS( "none");
                                
                            }
                            return
                        }
                        
                        
                        
                        logger.log("webloginlog: Calling userNeedsReauthentication")
                        self.loginManager?.userNeedsReauthentication{ error in
                            
                            
                            if error != nil {
                                logger.log("webloginlog: Error with userNeedsReauthentication")
                                
                                DispatchQueue.main.async {
                                    
                                    
                                    self.sendSignedTokenToJS("none")
                                    completion(error)
                                    
                                }
                                return
                            }
                            logger.info( "webloginlog: User successfully reauthenticated. Proceeding with login.")
                            completion(nil)
                        }
                        
                        
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
    func logWindowState(_ message: String) {
        DispatchQueue.main.async {
            let key = NSApp.keyWindow
            let main = self.view.window
            logger.log("webloginlog: STATE \(message): keyWindow=\(String(describing: key))  isKey? \(key?.isKeyWindow ?? false)  visible? \(key?.isVisible ?? false)  self.view.window=\(String(describing: main))")
        }
    }
    private func dumpWindowLifecycle(_ label: String) {
        DispatchQueue.main.async {
            let now = ISO8601DateFormatter().string(from: Date())
            let frontApp = NSWorkspace.shared.frontmostApplication
            let frontBundle = frontApp?.bundleIdentifier ?? "nil"
            let keyWin = NSApp.keyWindow
            let mainWin = self.view.window
            logger.log("webloginlog: WL \(now) \(label): frontApp=\(frontBundle) frontAppName=\(frontApp?.localizedName ?? "nil") keyWindow=\(String(describing: keyWin)) isKey=\(keyWin?.isKeyWindow ?? false) keyVisible=\(keyWin?.isVisible ?? false) selfWindow=\(String(describing: mainWin)) selfVisible=\(mainWin?.isVisible ?? false) selfIsKey=\(mainWin?.isKeyWindow ?? false)")
        }
    }
    // Call this once in viewDidLoad() to start logging
     func enableWindowLifecycleLogging() {
        NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main
        ) { note in
            if let w = note.object as? NSWindow {
                logger.log("webloginlog: WL-NOTIF: didBecomeKey -> \(w) visible:\(w.isVisible) alpha:\(w.alphaValue)")
            }
        }
        NotificationCenter.default.addObserver(
            forName: NSWindow.didResignKeyNotification, object: nil, queue: .main
        ) { note in
            if let w = note.object as? NSWindow {
                logger.log("webloginlog: WL-NOTIF: didResignKey -> \(w) visible:\(w.isVisible) alpha:\(w.alphaValue)")
            }
        }
        NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeMainNotification, object: nil, queue: .main
        ) { note in
            if let w = note.object as? NSWindow {
                logger.log("webloginlog: didBecomeMain -> \(w) visible:\(w.isVisible) alpha:\(w.alphaValue)")
            }
        }
        NotificationCenter.default.addObserver(
            forName: NSWindow.didResignMainNotification, object: nil, queue: .main
        ) { note in
            if let w = note.object as? NSWindow {
                logger.debug("webloginlog: WL-NOTIF: didResignMain -> \(w) visible:\(w.isVisible) alpha:\(w.alphaValue)")
            }
        }
    }

    // Call this helper to dump state whenever you want
    private func dumpActivationState(_ label: String) {
        DispatchQueue.main.async {
            let now = ISO8601DateFormatter().string(from: Date())
            let front = NSWorkspace.shared.frontmostApplication
            let key = NSApp.keyWindow
            let main = NSApp.mainWindow
            let selfWin = self.view.window
            logger.debug("webloginlog: WL-STATE \(now) \(label): frontApp=\(front?.bundleIdentifier ?? "nil") frontName=\(front?.localizedName ?? "nil") keyWindow=\(String(describing: key)) keyIsKey=\(key?.isKeyWindow ?? false) mainWindow=\(String(describing: main)) selfWindow=\(String(describing: selfWin)) selfIsVisible=\(selfWin?.isVisible ?? false) selfIsKey=\(selfWin?.isKeyWindow ?? false)")
        }
    }

    
    
}
