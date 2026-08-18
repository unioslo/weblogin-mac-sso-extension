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
//  AuthenticationViewController.swift
//  ssoe
//
//  Created by Francis Augusto Medeiros-Logeay on 22/10/2025.
//

import Cocoa
import AuthenticationServices
import WebKit
import OSLog
import CryptoKit
import LocalAuthentication


private let kService = "Weblogin SSO Session Cache"
let logger = Logger(subsystem: "no.uio.WebloginSSO", category: "general")

class AuthenticationViewController: NSViewController, WKNavigationDelegate   {

    
      
        var overlayView: NSView!
        var spinner: NSProgressIndicator!
        var overlayLabel: NSTextField!

        var url:URL?
        var authorizationRequest: ASAuthorizationProviderExtensionAuthorizationRequest?
        var kCallbackURLString = ""
        var saml = false
        // Define the IDP root (the url of the Keycloak instance)
        var referer = ""
        var is_post : Bool = false
        var post_done : Bool = false
        var postHeaders: [String:String] = [:]
        var idpLog = 0
        private var firstResponseChecked = false
        private var showedInteractiveLogin = false
        var timer: Timer?
        var hiddenHeightConstraint: NSLayoutConstraint?
        var showingHeightConstraint: NSLayoutConstraint?
        var isDeviceRegistrationFlow: Bool = false
        var isMainViewHidden: Bool = false {
            didSet {
            view.isHidden = isMainViewHidden
            hiddenHeightConstraint?.isActive = isMainViewHidden
            showingHeightConstraint?.isActive = !isMainViewHidden
            // Don't forget to call layoutIfNeeded() when you messing with the constraints
                view.layer?.setNeedsLayout()
                }
            }
        var signedTokenToSend: String?
        var baseURL = ""
        var loginManager: ASAuthorizationProviderExtensionLoginManager?
        var mdmConfig: (baseURL: String, issuer: String, clientID: String, audience: String)?
        var isRequiredAction: Bool = false
        var postSaml:Bool = false
        var registrationWebView: WKWebView?
        var authSession: ASWebAuthenticationSession?
        weak var authViewController: AuthenticationViewController?


    
       @IBOutlet weak var webView: WKWebView!
       @IBOutlet weak var cancelButton: NSButton!

       @IBAction func cancelButtonPressed(_ sender: Any) {
           if (isDeviceRegistrationFlow){
               RegistrationState.shared.registrationCompletion?(.failed)
               RegistrationState.shared.clear()
               
           }
           self.authorizationRequest?.doNotHandle()
       }
    


    override func viewDidLoad(){
        super.viewDidLoad()
       // loadMDMConfig()
        
        

  
        
        logger.log("webloginlog: viewDidLoad")
      //  guard let baseURL = self.mdmConfig?.baseURL else {
      //      return
      //  }

                
        
       // self.baseURL = baseURL
        // Overlay config
        
        
            // Create overlay
            overlayView = NSView()
            overlayView.wantsLayer = true
            overlayView.layer?.backgroundColor = NSColor(calibratedWhite: 0, alpha: 0.75).cgColor
            overlayView.isHidden = true
            overlayView.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(overlayView)

            // Pin overlay to edges
            NSLayoutConstraint.activate([
                overlayView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                overlayView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                overlayView.topAnchor.constraint(equalTo: view.topAnchor),
                overlayView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
            ])

            // Add spinner
            spinner = NSProgressIndicator()
            spinner.style = .spinning
            spinner.controlSize = .large
            spinner.isIndeterminate = true
            spinner.startAnimation(nil)
            spinner.appearance = NSAppearance(named: .darkAqua) ?? NSAppearance()
            spinner.translatesAutoresizingMaskIntoConstraints = false
            overlayView.addSubview(spinner)

            // Add “Processing…” label
            overlayLabel = NSTextField(labelWithString: "Registering...")
            overlayLabel.font = NSFont.systemFont(ofSize: 16, weight: .semibold)
            overlayLabel.textColor = NSColor.white
            overlayLabel.alignment = .center
            overlayLabel.translatesAutoresizingMaskIntoConstraints = false
            overlayView.addSubview(overlayLabel)

            // Center spinner + label
            NSLayoutConstraint.activate([
                spinner.centerXAnchor.constraint(equalTo: overlayView.centerXAnchor),
                spinner.centerYAnchor.constraint(equalTo: overlayView.centerYAnchor, constant: -10),

                overlayLabel.topAnchor.constraint(equalTo: spinner.bottomAnchor, constant: 8),
                overlayLabel.centerXAnchor.constraint(equalTo: overlayView.centerXAnchor)
            ])

        webView.navigationDelegate=self
        webView.configuration.allowsInlinePredictions = true
        webView.isInspectable = true
        webView.pageZoom = 0.8



        
    }
    override func viewDidAppear() {
        _ = self.view
       


        
        if (!RegistrationState.shared.isRegistrationInProgress){
            logger.info("webloginlog: viewDidAppear called.")


            }
            isMainViewHidden = true
            view.isHidden = true
            // view.window?.setContentSize(NSMakeSize(820, 600))

        // During registration the web login runs in ASWebAuthenticationSession
        // (its own window), so this view controller's window has no content and
        // would otherwise show as an empty square. Keep the window as a valid
        // presentation anchor but make it invisible to the user.
        if RegistrationState.shared.isRegistrationInProgress {
            view.window?.alphaValue = 0.0
            view.window?.isOpaque = false
            view.window?.hasShadow = false
        }
    }

    override var nibName: NSNib.Name? {
        return NSNib.Name("AuthenticationViewController")
        }
}


extension AuthenticationViewController: ASAuthorizationProviderExtensionAuthorizationRequestHandler {
    
   
            
    public func beginAuthorization(with request: ASAuthorizationProviderExtensionAuthorizationRequest) {
        destroyRegistrationWebView()
        self.authorizationRequest = request
        self.firstResponseChecked = false
        self.showedInteractiveLogin = false
        self.loginManager = request.loginManager

        logger.log("webloginlog: Received an authentication request from: \(request.callerBundleIdentifier)")
        
        logger.log("webloginlog: Is a registration in Progress? \(RegistrationState.shared.isRegistrationInProgress)")
        
        if RegistrationState.shared.isRegistrationInProgress {
            logger.log("webloginlog: Registration in progress. Don't display the webview")
            authorizationRequest?.doNotHandle()
            return
            
        }
        // Load ExtensionData early
        guard let tempLoginManager = request.loginManager else {
            logger.error("webloginlog: No loginManager in authorization request")
            authorizationRequest?.doNotHandle()
            return
        }

        let extensionData = tempLoginManager.extensionData
        guard let baseURLString = extensionData["BaseURL"] as? String else {
            logger.error("webloginlog: BaseURL not found in ExtensionData during authorization")
            authorizationRequest?.complete(error: ASAuthorizationError(.canceled))
            return
        }

        self.baseURL = baseURLString
        loadMDMConfig(loginManager: tempLoginManager)

        webView.configuration.userContentController.add(self, name: "pssoStepUp")

        let sharedDefaults = UserDefaults(suiteName: "group.no.uio.weblogin")
        let disableSSO = sharedDefaults?.bool(forKey: "disable_sso") ?? false
        let deviceRegistered = request.loginManager?.isDeviceRegistered ?? false && request.loginManager?.isUserRegistered ?? false
        let userRegistered = request.loginManager?.isUserRegistered ?? false && request.loginManager?.isUserRegistered ?? false
        
        logger.log("webloginlog: is sso disabled? \(disableSSO)")
        logger.log("webloginlog: is device and user registered? \(userRegistered && deviceRegistered)")

        if disableSSO || !deviceRegistered || !userRegistered {
            logger.log("webloginlog: SSO is disabled or the device is not registered. Won't display browser.")
            webView.configuration.userContentController.removeAllScriptMessageHandlers()
            authorizationRequest?.doNotHandle()
            return
        }

        guard let baseURL = URL(string: baseURLString) else {
            logger.error("webloginlog: Invalid BaseURL format")
            authorizationRequest?.complete(error: ASAuthorizationError(.canceled))
            return
        }
        let authorizationURLs = [ "\(baseURL)/protocol/openid-connect/auth", "\(baseURL)/protocol/saml"]
        
        var startAuthorization = false
      
        for authorizationURL in authorizationURLs {
            
            logger.info("webloginlog: checking authorization url: \(authorizationURL)")
            if request.url.absoluteURL.absoluteString.starts(with: authorizationURL) {
                logger.info("webloginlog: beginning authorization url: \(authorizationURL)")
                
                /*
                if let components = URLComponents(url: request.url.absoluteURL, resolvingAgainstBaseURL: false),
                   let kc_action = components.queryItems?.first(where: { $0.name == "kc_action" })?.value {
                    logger.log("webloginlog: has kc_action: \(kc_action). Skipping auth.")
                    break
                    
                }
                 */
                 
                 
                startAuthorization = true
                
                
                
                self.isDeviceRegistrationFlow = false
                break
            }
            
        }
        
        if (!startAuthorization) {
            
            webView.configuration.userContentController.removeAllScriptMessageHandlers()
            authorizationRequest?.doNotHandle()
            return
        }
        
        let loginManager = request.loginManager
        self.loginManager = loginManager
        if let loginManager {
            updateConfiguration(loginManager: loginManager)
        }
       
        let tokens = loginManager?.ssoTokens
        if let tokens = request.loginManager?.ssoTokens {
            logger.log( "webloginlog: There are SSO Tokens. Using them.")
            insertPssoTokens(request: request, tokens: tokens)
        }else {
            logger.log("webloginlog: There are no SSO Tokens. Trying to retrieve them.")
            loginManager?.userNeedsReauthentication{ error in

               
                if let error {
                    logger.error("webloginlog: Error: \(error.localizedDescription)")
                    self.webView.configuration.userContentController.removeAllScriptMessageHandlers()
                    
                
                
                    self.authorizationRequest?.doNotHandle()


                }
                else{
                    let tokens  = self.loginManager?.ssoTokens
                    logger.log("webloginlog: Got tokens.")
                    self.insertPssoTokens(request: request, tokens: tokens)
                }
            }
            
        }
        
       
    }
    
    

        
    
    
    
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard  let webViewURL = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }
     
        if (RegistrationState.shared.isRegistrationInProgress){
            logger.log( "webloginlog: Registration login flow.")
            if webViewURL.absoluteString.starts(with: "weblogin-sso://idp-login-redirect"){
                
                var hasCode = false
                if let components = URLComponents(url: webViewURL, resolvingAgainstBaseURL: false)  {
                    let code =  components.queryItems?.first(where: { $0.name == "code" })?.value
           

                    if code != nil {

                        hasCode = true
                        showProcessingOverlay()
                        self.authorizationRequest?.complete()
                        
                        //self.authorizationRequest?.doNotHandle()
                        
                      
                           // Force redraw
                           //self.view.displayIfNeeded()
                //        decisionHandler(.cancel)
                        Task { @MainActor in

                            do {
                                let token = try await exchangeCodeForToken(code: code!)
                                let access_token = decodeJWT(token.access_token)
                                if let idpUsername = access_token?["preferred_username"] as? String {
                                    RegistrationState.shared.idpUsername = idpUsername
                                    logger.debug("webloginlog: Will now call the \(RegistrationState.shared.registrationType!) registration")

                                    
                                    
                                     if RegistrationState.shared.registrationType == "device" {
                                        self.registerDevice(accessToken: token.access_token, userName: idpUsername)
                                    }else {
                                        self.registerUser(accessToken: token.access_token)
                                    }
                                    RegistrationState.shared.isRegistrationInProgress = false
                                }else {
                                    logger.error("webloginlog: No preferred_username in access token")
                                    RegistrationState.shared.registrationCompletion?(.failed)
                                    return
                                }
                                
                            }catch {
                                logger.error("webloginlog: Fetching the token failed somehow: \(error)")
                                RegistrationState.shared.registrationCompletion?(.failed)
                                RegistrationState.shared.clear()
                                return
                                
                            }
                            
                        }
                    }
                    
                    
                }
                if !hasCode{
                    RegistrationState.shared.registrationCompletion?(.failed)
                    RegistrationState.shared.clear()
                }
              
                decisionHandler(.cancel)
                webView.configuration.userContentController.removeAllScriptMessageHandlers()
                self.authorizationRequest?.doNotHandle()
                logger.debug("webloginlog: End of registration flow block")
             
                return
                
            }else {
                logger.debug("webloginglog: Registration block intermediary page - let it go.")
                decisionHandler(.allow)
            }
            return
        }
       
        guard let request = navigationAction.request as? NSMutableURLRequest, let url = url else {
            decisionHandler(.allow)
            return
            
        }
        
        
        //if showedInteractiveLogin { self.view.isHidden = false }
    
        // Here we handle SAML authentication
        // The difference is that there's no callback, so we detect
        // the referer. When the IDP returns to the referer
        // and a POST is done, here's the SAML request being posted.
        if (self.saml){
            logger.debug( "webloginlog: Handling SAML request")
            // POST checks
            var containsSAMLResponse: Bool = false
            var httpBody: String? = ""
            if let httpBodyData = request.httpBody {
                httpBody = String(data: httpBodyData, encoding: .utf8)
            
                containsSAMLResponse = httpBody!.contains("SAMLResponse")
                logger.debug("webloginlog: Contains SAML Response: \(containsSAMLResponse)")

            }
            
            
        
         
            
            // Redirect checks
            let idpURL = url.absoluteString.starts(with: baseURL)
            let components = URLComponents(url: webViewURL, resolvingAgainstBaseURL: false)
            let samlResponse =  components?.queryItems?.first(where: { $0.name == "SAMLResponse" })?.value
            
            // REDIRECT
            if idpURL == true && samlResponse != nil {
                logger.debug("webloginlog: This is a SAML Redirect flow.")
                decisionHandler(.cancel)
                webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                    self.postHeaders = [
                        "Location": webViewURL.absoluteString,
                        "Set-Cookie": self.combineCookies(cookies: cookies),
                        "Content-Type": "text/html; charset=utf-8"
                    ]
                    let httpVersion = "HTTP/1.1"
                    if let response = HTTPURLResponse(url: url, statusCode: 303, httpVersion: httpVersion, headerFields: self.postHeaders) {
                        webView.configuration.userContentController.removeAllScriptMessageHandlers()
                        self.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                        return
                        
                        
                    }
                }
                return
            }
            let httpMethod = request.httpMethod
            logger.debug("webloginlog: HttpMethod: \(httpMethod)")
       
            
            // POST
            if (request.httpMethod == "POST" && idpURL == true && containsSAMLResponse == true ){
                    
                        is_post = true
                        decisionHandler(.cancel)
                        var html = """
                                <html>
                                <body onload="document.forms[0].submit()">
                                <form action="\(webViewURL.absoluteString)" method="post">

                                """
                        let saml_response = httpBody!.split(separator: "&")
                        
                        for param in saml_response {
                            let key_value = param.split(separator: "=",maxSplits: 1)
                            let paramName = String(key_value[0])
                            let rawValue = String(key_value[1])
                            let decoded = rawValue.removingPercentEncoding ?? rawValue
                            let escaped = htmlEscape(decoded)
                            let line = "<input type=\"hidden\" name=\"\(paramName)\" value=\"\(escaped)\">"
                            html += line
                        }
                        let theForm = html + """
                                    
                                    </form>
                                    </body>
                                    </html>
                            """
                
                        webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                            self.postHeaders = [
                                   // "Location": webViewURL.absoluteString,
                                    "Set-Cookie": self.combineCookies(cookies: cookies),
                                    "Content-Type": "text/html; charset=utf-8"
                                ]
                              let httpVersion = "HTTP/1.1"
                            if let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: httpVersion, headerFields: self.postHeaders) {
                                
                                let data = theForm.data(using: .utf8)
                                webView.configuration.userContentController.removeAllScriptMessageHandlers()
                                self.authorizationRequest?.complete(httpResponse: response, httpBody: data)
                                return
                                
                                
                            }
                                
                            }
                        return
                    }
                    decisionHandler(.allow)
                    return
                }
                else {
                    logger.debug("webloginlog: Not a SAML request. ")
                }
        
        
       // let components = URLComponents(url: webViewURL, resolvingAgainstBaseURL: false)
    //    let code =  components?.queryItems?.first(where: { $0.name == "code" })?.value
        /*
        var callbackIsIdpInternalClient = false
        if webViewURL.absoluteString.starts(with: self.baseURL) && self.saml == false && kCallbackURLString.starts(with: baseURL) {
            callbackIsIdpInternalClient = true
            
        }
         */
        
        
        // needs fixing
        if webViewURL.absoluteString.starts(with: kCallbackURLString) {
       
            logger.debug("webloginlog: Intercepted redirect to callback. Send it to the browser." )

            // Stop navigation
            if (self.saml == true){
                decisionHandler(.allow)
                return
            }
            
            decisionHandler(.cancel)
           
            
     
            
            // Extract cookies
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
               
                    let headers: [String:String]  = [
                        "Location": webViewURL.absoluteString,
                        "Set-Cookie": self.combineCookies(cookies: cookies)
                    ]
                
                 
                
                
                    if let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: headers) {
                        
                        logger.debug("webloginlog: Sending redirect response to browser from intercepted url.")
                        webView.configuration.userContentController.removeAllScriptMessageHandlers()
                        self.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                        return
                        
                    } else {
                        logger.error("webloginlog: Failed to construct HTTPURLResponse for oidc.")
                    }
                
                
            }

            return
        }

        // Allow other navigation
        decisionHandler(.allow)
    }

    

    
    public func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
        guard  let url = url, let webViewURL = webView.url else {
            return
        }
    
        
        if let redirectURL = webViewURL.baseURL?.absoluteString {
            logger.log("webloginlog: Entering redirection to url starting with: \(redirectURL)")
        }

        if (RegistrationState.shared.isRegistrationInProgress){
            
            return
        }
 
        
       
      
        /*
        var callbackIsIdpInternalClient = false
        if webViewURL.absoluteString.starts(with: self.baseURL) && self.saml == false && kCallbackURLString.starts(with: baseURL) {
            callbackIsIdpInternalClient = true
            
        }
        */
        
        
        if (webViewURL.absoluteString.starts(with: (kCallbackURLString)) ) {
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies({ cookies in
               
                
                let headers: [String:String] = [
                    "Location": webViewURL.absoluteString,
                    "Set-Cookie": self.combineCookies(cookies: cookies)
                ]
                 
                
                
                    // webView.configuration.websiteDataStore.
              // let headers: [String:String] = [:]
             
               
         //       self.storeCookies(cookies)
                
                
                    
                    
                
                if webViewURL.absoluteString.starts(with: self.baseURL) && self.saml == true {
                    logger.log("webloginlog: redirecting to the idp. continue on the webview.")
                    return
                }
                
                    if let response = HTTPURLResponse.init(url: url, statusCode: 302, httpVersion: nil, headerFields: headers) {
                        webView.configuration.userContentController.removeAllScriptMessageHandlers()
                        self.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                    }else {
                        logger.error("webloginlog: Failed to construct HTTPURLResponse.")
                    }
                
            })
           
        }else {
            logger.log("webloginlog: not the callback redirection. continue")
        }
        
        
    
    }
    
    
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {

        if (RegistrationState.shared.isRegistrationInProgress){
            return
        }
      

        
        guard   let webViewURL = webView.url else {
            logger.error("webloginlog: I don't have an url, or the webview doesn't have one")
            return
        }
        
  

        let isRequiredAction = webViewURL.absoluteString.starts(with: baseURL) && webView.url?.relativePath.contains("/login-actions") == true
        logger.log("webloginlog: this is a required action: \(isRequiredAction)")
            
        // Run a minimal DOM probe for a visible password input
        
        if webView.url?.relativePath.contains("/login-actions/required-action") == true {
            self.isRequiredAction = true
        }
        logger.log("webloginlog: this is a required action: \(isRequiredAction)")

        
        
        
            // Run a minimal DOM probe for a visible password input
        let js = """
        (function() {
            return {
                hasPasswordField: !!document.querySelector('input[type="password"]'),
                hasReauthenticate: !!document.querySelector('#reauthenticate')
            };
        })();
        """
            
        webView.evaluateJavaScript(js) { [weak self] result, error in
            guard let self = self else { return }
            if let error = error {
                logger.error("webloginlog: First-response JS probe error: \(error.localizedDescription)")
                return
            }
            
            if let dict = result as? [String: Any] {
                
                
                let hasPasswordField = dict["hasPasswordField"] as? Bool ?? false
                let hasReauthenticate = dict["hasReauthenticate"] as? Bool ?? false
                
                
                if hasReauthenticate == true {
                    return;
                }
                
                logger.debug("webloginlog: the form has a password field: \(hasPasswordField)")
                
                logger.debug("webloginlog: is post \(self.is_post)")
                if ((self.saml == false && hasPasswordField == true) || (self.saml == true && is_post != true && hasPasswordField == true) || (isRequiredAction == true && is_post != true)) &&  !self.postSaml {
                    
                    self.postSaml = false
                    // DispatchQueue.main.async {
                    if let win = self.view.window {
                        win.makeKeyAndOrderFront(nil)
                        // set desired content size if needed
                        win.setContentSize(NSMakeSize(700, 560))
                    }
                    self.view.window?.makeKeyAndOrderFront(nil)
                    self.view.window?.setContentSize(NSMakeSize(700,560))
                    self.hideProcessingOverlay()
                    self.isMainViewHidden = false
                    // Don't forget to call layoutIfNeeded() when you messing with the constraints
                    // self.cancelButton.isHidden = false
                    self.view.alphaValue = 1.0
                    self.view.window?.isOpaque = true
                    self.view.needsLayout = true
                    self.webView.isHidden = false
                    // Force redraw
                    self.view.displayIfNeeded()
                    self.view.isHidden = false
                    self.view.layoutSubtreeIfNeeded()
                    //      }
                    
                    
                    
                    logger.log("webloginlog: Detected interactive login on first response. Showing UI immediately.")
                } else {
                    showWindowIfDelay()
                    logger.log("webloginlog: No password field on first response; keeping UI hidden for SSO.")
                }
            }
            
        }
       // }
        
        
        
    }
    
    
    fileprivate func combineCookies(cookies: [HTTPCookie]) -> String {
        let dateFormatter = ISO8601DateFormatter.init()
        var cookiesStrings = [String]()
        for cookie in cookies {
            var cookieString = [String]()
            cookieString.append("\(cookie.name)=\(cookie.value)")
            cookieString.append("domain=\(cookie.domain)")
            cookieString.append("path=\(cookie.path)")
            if let expires = cookie.expiresDate {
                cookieString.append("expires=\(dateFormatter.string(from: expires))")
            }
            if cookie.isSecure {
                cookieString.append("secure")
            }
            if cookie.isHTTPOnly {
                cookieString.append("httponly")
            }
            if let sameSite = cookie.sameSitePolicy {
                cookieString.append("SameSite=\(sameSite.rawValue)")
            }
            cookiesStrings.append(cookieString.joined(separator: "; "))
        }
        return cookiesStrings.joined(separator: ", ")
    }
    
    func storeCookies(_ cookies: [HTTPCookie] ) {
        if let data = try? NSKeyedArchiver.archivedData(withRootObject: cookies, requiringSecureCoding: false) {
            
            
            let attributes = [kSecClass: kSecClassGenericPassword,
                        kSecAttrService: kService,
          kSecUseDataProtectionKeychain: false,
                          kSecValueData: data] as [String: Any]
            _ = SecItemDelete(attributes as CFDictionary)
            let _ = SecItemAdd(attributes as CFDictionary, nil)
        }
    }
    
    
    
    
    @discardableResult func getCookies() -> [HTTPCookie]? {
        let attributes = [kSecClass: kSecClassGenericPassword,
                    kSecAttrService: kService,
               kSecReturnAttributes: true,
      kSecUseDataProtectionKeychain: false,
                     kSecReturnData: true] as [String: Any]
        var item: CFTypeRef?
        if  SecItemCopyMatching(attributes as CFDictionary, &item) == 0 {
            if let result = item as? [String:AnyObject],
               let cookiesRaw = result["v_Data"] as? Data,
               let cookies = try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(cookiesRaw) as? [HTTPCookie] {
                if cookies.count == 0 {
                    return nil
                } else {
                    return cookies
                }
            }
        }
        return nil
    }
    func showWindowIfDelay() {
        self.timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: false) { timer in
            logger.debug("webloginlog: more than 5 seconds without SSO - we make the web browser visible.")// Perform actions here
            self.isMainViewHidden = false
            if let win = self.view.window {
                       win.makeKeyAndOrderFront(nil)
                       // set desired content size if needed
                       win.setContentSize(NSMakeSize(700, 560))
                   }
          
            self.isMainViewHidden = false
                    // Don't forget to call layoutIfNeeded() when you messing with the constraints
           // self.cancelButton.isHidden = false
            self.view.alphaValue = 1.0
            self.view.window?.isOpaque = true
            
            self.view.needsLayout = true
               self.view.layoutSubtreeIfNeeded()
          
               // Force redraw
               self.view.displayIfNeeded()

        }
       }
    
    
}

extension AuthenticationViewController: ASAuthorizationProviderExtensionRegistrationHandler {
    
    func configuration(loginManager: ASAuthorizationProviderExtensionLoginManager) -> ASAuthorizationProviderExtensionLoginConfiguration {
        
        logger.debug("webloginlog: getting configuration")

        let extensionData = loginManager.extensionData
        
        let clientID = extensionData["ClientID"] as? String ?? "fallback-client"
        let baseURL  = extensionData["BaseURL"] as? String ?? "fallback-baseURL"
        let issuer = extensionData["Issuer"] as? String ?? "fallback-issuer"
        let audience = extensionData["Audience"] as? String ?? "fallback-audience"
        let useRefreshToken = extensionData["UseRefreshToken"] as? Bool ?? false
        
        let tokenEndpointURL = URL(string: baseURL+"/psso/token")!
        let jwksEndpointURL = URL(string: baseURL+"/protocol/openid-connect/certs")!
        let authEndpointURL = URL(string: baseURL+"/psso/authurl")!
        
        
        
      
        logger.debug("webloginlog: auth endpoint is \(authEndpointURL)")
        
        let config = ASAuthorizationProviderExtensionLoginConfiguration(
            clientID: clientID,
            issuer: issuer,
            tokenEndpointURL: tokenEndpointURL,
            jwksEndpointURL: jwksEndpointURL,
            audience: audience,
            
        )
        
        if let nonceEndpointURL = URL(string: baseURL+"/psso/nonce") {
            config.nonceEndpointURL = nonceEndpointURL
        }
        
        if useRefreshToken {
            config.refreshEndpointURL = tokenEndpointURL
        }
        config.keyEndpointURL = tokenEndpointURL
        config.nonceResponseKeypath = "nonce"
        config.groupResponseClaimName = "groups"
        config.audience = audience
        if #available(macOS 27.0, *) {
            
            config.includePlatformSSOAuthorizationScopes = extensionData["includePlatformSSOAuthorizationScopes"] as? Bool ?? false
            logger.log("webloginlog: includePlatformSSOAuthorizationScopes: \(config.includePlatformSSOAuthorizationScopes)")
            config.federationType = .dynamicOpenID
            config.federationUserPreauthenticationURL = authEndpointURL
            config.authorizationURLKeypath = "authorizationURL"

        }
        
        
        return config
    }
    
    func beginUserRegistration(
        loginManager: ASAuthorizationProviderExtensionLoginManager,
        userName: String?,
        method authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod,
        options: ASAuthorizationProviderExtensionRequestOptions = [],
        completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void
    ){

        logger.log("webloginlog: Beginning user registration")
        // Set self.loginManager early so getNonceFromIdp can use it if needed
        self.loginManager = loginManager
        if !options.contains(.userInteractionEnabled){
            logger.log("webloginlog: User interaction enabled. Aborting.")
            completion(.userInterfaceRequired)
            return
            
        }

        logger.debug("webloginlog: is device registered? \(loginManager.isDeviceRegistered)")
        logger.info("webloginlog: Starting user registration")
        
        RegistrationState.shared.loginManager = loginManager
        RegistrationState.shared.registrationCompletion = completion
        RegistrationState.shared.isRegistrationInProgress = true
        RegistrationState.shared.registrationType = "user"
        let token = RegistrationState.shared.accessToken
        
        if token != nil {
            logger.log("webloginlog: user has token. Proceeding to user registration")
            registerUser(accessToken: token!)
            
        }else {
            
            /*
             
             Old webview code
             
            self.isDeviceRegistrationFlow = true
            self.isMainViewHidden = false
            if let win = self.view.window {
                win.makeKeyAndOrderFront(nil)
                // set desired content size if needed
                win.setContentSize(NSMakeSize(700, 560))
            }
            
            webView.navigationDelegate=self
            webView.configuration.allowsInlinePredictions = true
            self.isMainViewHidden = false
            // Don't forget to call layoutIfNeeded() when you messing with the constraints
            // self.cancelButton.isHidden = false
            self.view.alphaValue = 1.0
            self.view.window?.isOpaque = true
            self.view.needsLayout = true
            self.view.layoutSubtreeIfNeeded()
            
            // Force redraw
            self.view.displayIfNeeded()
             */
            loginManager.presentRegistrationViewController{
                error in
                if let error = error {
                    logger.error("webloginlog: \(error)")
                    RegistrationState.shared.isRegistrationInProgress = false
                    completion(.failed)
                    return

                }

                
               if options.contains(.setupAssistant), let silentRegistration = loginManager.extensionData["SilentUserRegistrationDuringSetupAssistant"], silentRegistration as! Bool, let refresh_token = loginManager.ssoTokens?["refresh_token"] as? String {
                    
                    self.doSilentUserRegistration(refresh_token: refresh_token, loginManager: loginManager)
                    
                    
                }else {
                    self.idpLogin(isSetupAssistant: options.contains(.setupAssistant),loginManager: loginManager)
                }
            }
        }
        
    }
    
    
    func beginDeviceRegistration(loginManager:
                                 ASAuthorizationProviderExtensionLoginManager, options:
                                 ASAuthorizationProviderExtensionRequestOptions = [],
                                 completion: @escaping
                                 (ASAuthorizationProviderExtensionRegistrationResult) ->
                                 Void) {
        logger.debug("webloginlog: beginDeviceRegistration")
        self.loginManager = loginManager
        loadMDMConfig(loginManager: loginManager)
        RegistrationState.shared.loginManager = loginManager
        RegistrationState.shared.registrationCompletion = completion
        RegistrationState.shared.isRegistrationInProgress = true
        RegistrationState.shared.registrationType = "device"
        self.isDeviceRegistrationFlow = true
        /*
         Old webview
         
        self.isMainViewHidden = false
        if let win = self.view.window {
            win.makeKeyAndOrderFront(nil)
            // set desired content size if needed
            win.setContentSize(NSMakeSize(700, 560))
        }
        
   
       // webView.navigationDelegate=self
       // webView.configuration.allowsInlinePredictions = true
        self.isMainViewHidden = false
        // Don't forget to call layoutIfNeeded() when you messing with the constraints
        // self.cancelButton.isHidden = false
        self.view.alphaValue = 1.0
        self.view.window?.isOpaque = true
        self.view.needsLayout = true
        self.view.layoutSubtreeIfNeeded()
        
        // Force redraw
        self.view.displayIfNeeded()
         */
        
        if loginManager.registrationToken == nil {
            logger.log("Device registration started using User Login.")
            loginManager.presentRegistrationViewController {
                error in

                if let error = error {
                    logger.error("webloginlog: \(error)")
                    RegistrationState.shared.isRegistrationInProgress = false
                    completion(.failed)
                    return
                }

                self.idpLogin(isSetupAssistant: options.contains(.setupAssistant),loginManager: loginManager)

                // completion(.userInterfaceRequired)



            }
        }else {
            logger.log("webloginlog: Device Registration started using Registration Token.")
            registerDevice(accessToken: "", userName: "")
        }
        
    }
    
    func idpLogin(isSetupAssistant: Bool, loginManager: ASAuthorizationProviderExtensionLoginManager) {
        logger.log("webloginlog: Starting IdP login")

        // Load ExtensionData directly
        let extensionData = loginManager.extensionData
        guard let baseURL = extensionData["BaseURL"] as? String else {
            logger.error("webloginlog: BaseURL not found in ExtensionData during idpLogin")
            RegistrationState.shared.isRegistrationInProgress = false
            if let completion = RegistrationState.shared.registrationCompletion {
                completion(.failed)
            }
            return
        }

        guard let clientID = extensionData["ClientID"] as? String else {
            logger.error("webloginlog: ClientID not found in ExtensionData during idpLogin")
            RegistrationState.shared.isRegistrationInProgress = false
            if let completion = RegistrationState.shared.registrationCompletion {
                completion(.failed)
            }
            return
        }

        var refreshToken : String?
        if isSetupAssistant {
            if let ssoTokens = loginManager.ssoTokens {
                refreshToken = ssoTokens[AnyHashable("refresh_token")] as? String
            }
        }

        RegistrationState.shared.accessToken = nil
        
        // Create PKCE code verifier and challenge
        let verifier = randomString(length: 64)
        let challenge = sha256Base64URL(verifier)
        
        // Store the verifier to use later when exchanging the code for a token
        RegistrationState.shared.pkceVerifier = verifier
        
        // Random state for anti-CSRF
        let state = UUID().uuidString
        
        // Build URL components
        var components = URLComponents(string: "\(baseURL)/protocol/openid-connect/auth")!
        
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: "weblogin-sso://idp-login-redirect"),
            URLQueryItem(name: "scope", value: "openid profile"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            // Optional extras:
            
            URLQueryItem(name: "prompt", value: "login")
        ]
        
        guard let authURL = components.url else {
            logger.error("Failed to construct Keycloak auth URL")
            RegistrationState.shared.isRegistrationInProgress = false
            RegistrationState.shared.registrationCompletion?(.failed)
            return
        }
        
        logger.debug("webloginlog: Presenting login page: \(authURL.absoluteString)")
        
        
        // new authentication:
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            let clientRequestId = UUID().uuidString

            var signedTokenToSend = ""
            // Handle async nonce fetching if refresh token exists
            if let refreshToken = refreshToken {
                Task {
                    var request = URLRequest(url: authURL)

                    if let nonce = try? await self.getNonceFromIdp(clientRequestId: clientRequestId, loginManager: loginManager) {
                        let signedToken = self.signToken(token: refreshToken, tokenType: "refresh_token", loginManager: loginManager, nonce: nonce, clientId: clientRequestId)

                        if let signedToken = signedToken {
                            signedTokenToSend = signedToken
                            request.setValue("Bearer \(signedToken)", forHTTPHeaderField: "Platform-SSO-Authorization")
                            logger.debug("webloginlog: Added Platform-SSO-Authorization header with refresh token")
                        }
                    } else {
                        logger.error("webloginlog: Failed to fetch nonce for refresh token")
                    }

                    await MainActor.run {
                        self.startLogin(authURL: authURL, refreshToken: signedTokenToSend, loginManager: loginManager)
                    }
                }
            } else {
                self.startLogin(authURL: authURL, refreshToken: signedTokenToSend, loginManager: loginManager)
            }
        }
        
        
       // destroyRegistrationWebView()
        
        /*
         
        // old webview
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            let clientRequestId = UUID().uuidString

            let configuration = WKWebViewConfiguration()
            configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
            configuration.userContentController.add(self, name: "weblogin")
            configuration.websiteDataStore = WKWebsiteDataStore.nonPersistent()
            let webView = WKWebView(frame: self.webView.frame, configuration: configuration)
            webView.navigationDelegate = self
            webView.isInspectable = true
            self.registrationWebView = webView
            self.isMainViewHidden = false
            self.view.addSubview(webView)
            self.view.addSubview(self.overlayView)

            // Handle async nonce fetching if refresh token exists
            if let refreshToken = refreshToken {
                Task {
                    var request = URLRequest(url: authURL)

                    if let nonce = try? await self.getNonceFromIdp(clientRequestId: clientRequestId, loginManager: loginManager) {
                        let signedToken = self.signToken(token: refreshToken, tokenType: "refresh_token", loginManager: loginManager, nonce: nonce, clientId: clientRequestId)

                        if let signedToken = signedToken {
                            request.setValue("Bearer \(signedToken)", forHTTPHeaderField: "Platform-SSO-Authorization")
                            logger.debug("webloginlog: Added Platform-SSO-Authorization header with refresh token")
                        }
                    } else {
                        logger.error("webloginlog: Failed to fetch nonce for refresh token")
                    }

                    await MainActor.run {
                        webView.pageZoom = 0.8
                        webView.load(request)
                    }
                }
            } else {
                // No refresh token, load directly
                webView.pageZoom = 0.8

                webView.load(URLRequest(url: authURL))
            }
        }
         */
    }
    
    func destroyRegistrationWebView() {
        DispatchQueue.main.async {
            guard let webView = self.registrationWebView else { return }
            logger.log("webloginlog: destroyRegistrationWebView")
            webView.stopLoading()
            webView.navigationDelegate = nil
            webView.removeFromSuperview()
            self.overlayView.removeFromSuperview()

            self.registrationWebView = nil
        }
    }
    
    func randomString(length: Int) -> String {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        return String((0..<length).compactMap { _ in characters.randomElement() })
    }
    
    func sha256Base64URL(_ input: String) -> String {
        let data = Data(input.utf8)
        let hash = SHA256.hash(data: data)
        let base64 = Data(hash).base64EncodedString()
        // Convert Base64 to Base64URL (RFC 7636)
        return base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    
    func registerDevice(accessToken: String, userName: String){
        guard let completion = RegistrationState.shared.registrationCompletion, let loginManager = RegistrationState.shared.loginManager
        else {
            logger.error("webloginlog: No loginManager and/or completion handler saved for device registration. Aborting.")
            return }

        // Load ExtensionData to get baseURL
        let extensionData = loginManager.extensionData
        guard let baseURLString = extensionData["BaseURL"] as? String else {
            logger.error("webloginlog: BaseURL not found in ExtensionData during device registration")
            completion(.failed)
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
        
        
        guard let signingKey =  loginManager.key(for: .sharedDeviceSigning),
              let encryptionKey = loginManager.key(for: .sharedDeviceEncryption)
        else {
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

        /* log the kids
        logger.log("webloginlog: Signing Key ID: \(signKeyId)")
        logger.log("webloginlog: Encryption Key ID: \(encKeyId)")
        */

        do {
            let config = configuration(loginManager: loginManager)

            let extensionData = loginManager.extensionData
            
            if let policy = biometricPolicyFromExtensionData(extensionData) {
                config.userSecureEnclaveKeyBiometricPolicy = policy
            }
             
            
            try config.setCustomLoginRequestBodyClaims( ["signKeyId": signKeyId, "encKeyId": encKeyId])
            try config.setCustomRefreshRequestBodyClaims(["signKeyId": signKeyId, "encKeyId": encKeyId])
            
            try loginManager.saveLoginConfiguration(config)
            let savedAudience = loginManager.loginConfiguration?.audience ?? "no_audience_saved"
           
        }catch{
            let config = configuration(loginManager: loginManager)
            let token = config.tokenEndpointURL.absoluteString
            logger.error("webloginlog: Failed to save the configuration \(error). Token URL: \(token)")
        }
        
        var nonce = nil as UUID?
        Task { @MainActor in
            do {
                let nonceValue = try await getNonceFromIdp(clientRequestId: clientRequestId, loginManager: loginManager)
                let nonceString = nonceValue?.uuidString ?? "no value"
                logger.debug("webloginlog; Got nonce: \(nonceString)")
                nonce = nonceValue
            } catch {
                logger.error("webloginlog: Error fetching nonce: \(error)")
                completion(.failed)
                return
            }

            // POST to your registration endpoint
            guard let url = URL(string: baseURLString+"/psso/enroll" ) else {
                completion(.failed)
                return
            }
            
            let nonceData = nonce!.uuidString.lowercased().data(using: .utf8)!
            let nonceHash = SHA256.hash(data: nonceData)
            let nonceHashData = Data(nonceHash)
            let attestCertificate = try await loginManager.attestKey(ofType: .sharedDeviceSigning,  clientDataHash: nonceHashData)
            
            
            let attestationB64 = attestCertificate.compactMap { cert -> String? in
                guard let data = SecCertificateCopyData(cert) as Data? else { return nil }
                return data.base64EncodedString(options: [])
            }
            
            
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue(clientRequestId, forHTTPHeaderField: "client-request-id")
            
            var registrationMethod : String
        
            switch loginManager.authenticationMethod {
            case .password:
                registrationMethod = "PASSWORD"
            case .userSecureEnclaveKey:
                registrationMethod = "SECURE_ENCLAVE"
            case .openID:
                registrationMethod = "OPENID"
            default:
                registrationMethod = "SECURE_ENCLAVE"
            }
            
            
            var params = [
                "DeviceSigningKey": signingKeyB64,
                "DeviceEncryptionKey": encryptionKeyB64,
                "SignKeyID": signKeyId,
                "EncKeyID": encKeyId,
                "nonce" : nonce!.uuidString.lowercased(),
                "attestation" : attestationB64,
                "registrationMethod" : registrationMethod
            ]
            
            if loginManager.registrationToken != nil {
                logger.log("webloginlog: using Registration Token for device registration.")
                params["registrationToken"] = loginManager.registrationToken
                
            } else {
                logger.log("webloginlog: using Access Token for device registration.")
                params["accessToken"] = accessToken
            }
            
            
            let jsonBody = try JSONSerialization.data(withJSONObject: params, options: [])
            request.httpBody = jsonBody
            
            let UrlString = url.absoluteString
            logger.debug("webloginlog: Sending registration to \(UrlString)")
            
            URLSession.shared.dataTask(with: request) { data, response, error in
                if let httpResponse = response as? HTTPURLResponse,
                   (200...299).contains(httpResponse.statusCode) || httpResponse.statusCode == 409 {
                    logger.log("webloginlog: Device successfully registered.")
                    completion(.success)
                    
                    RegistrationState.shared.clear()
                    return
                } else {
                    let responseHTTP =  response as? HTTPURLResponse
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
    
    func registerUser(accessToken: String){
        guard let loginManager = RegistrationState.shared.loginManager, let completion = RegistrationState.shared.registrationCompletion else {
            logger.error("webloginlog: No Login Manager or Registration Completion")
            RegistrationState.shared.isRegistrationInProgress = false

            return }

        logger.log("webloginlog: Begin User registration")

        // Load ExtensionData to get baseURL
        let extensionData = loginManager.extensionData
        guard let baseURLString = extensionData["BaseURL"] as? String else {
            logger.error("webloginlog: BaseURL not found in ExtensionData during user registration")
            RegistrationState.shared.isRegistrationInProgress = false

            completion(.failed)
            return
        }

        guard let userName = RegistrationState.shared.idpUsername else {
            logger.error("webloginlog: No username found.")
            RegistrationState.shared.isRegistrationInProgress = false
            completion(.failed)
            return
        }
        
        
        
        
        
        logger.log("webloginlog: User being registered is: \(userName)")
        
        let config = ASAuthorizationProviderExtensionUserLoginConfiguration.init(loginUserName: userName)
        config.loginUserName = userName
        
        do {
            try loginManager.saveUserLoginConfiguration(config)
            
        }catch{
            
            logger.error("webloginlog: Failed to save the configuration \(error).")
            RegistrationState.shared.isRegistrationInProgress = false
            completion(.failed)
        }
        
        if loginManager.authenticationMethod == .password {
            let audience = loginManager.loginConfiguration?.audience
            logger.log("webloginlog: The registration method is Password.")

            logger.log("webloginlog: The audience in user registration is: \(audience as NSObject?)")
            let userDeviceSigning = loginManager.key(for: .userDeviceSigning)
            RegistrationState.shared.isRegistrationInProgress = false
            completion(.success)
            return
        }
        
        if #available(macOS 27.0, *) {
            if loginManager.authenticationMethod == .openID {
                let audience = loginManager.loginConfiguration?.audience
                logger.log("webloginlog: The registration method is OPENID.")
                
                logger.log("webloginlog: The audience in user registration is: \(audience as NSObject?)")
                let userDeviceSigning = loginManager.key(for: .userDeviceSigning)
                RegistrationState.shared.isRegistrationInProgress = false
                completion(.success)
                return
            }
        }
        logger.log("webloginlog: The registration method is Secure Enclave.")

        
        loginManager.resetUserSecureEnclaveKey()
        guard let userKey = loginManager.key(for: .userSecureEnclaveKey) else {
            logger.error("webloginlog: No user key found.")
            RegistrationState.shared.isRegistrationInProgress = false

            completion(.failed)
            return
        }

        guard let userPublicKey = SecKeyCopyPublicKey(userKey) else {
                logger.error("webloginlog: Can't export the public key for the user.")
            RegistrationState.shared.isRegistrationInProgress = false

                completion(.failed)
                return
                
            }
    
       
        let userKeyId = computeKid(from: userPublicKey)
        let userKeyData = SecKeyCopyExternalRepresentation(userPublicKey, nil)! as Data
        let userKeyB64 = userKeyData.base64EncodedString(options: [])
        
        
        logger.debug("webloginlog: username registered from idp is \(userName)")
        
      
        
        var nonce = nil as UUID?
        let clientRequestId = UUID().uuidString
        Task {
            do {
                let nonceValue = try await getNonceFromIdp(clientRequestId: clientRequestId, loginManager: loginManager)
                logger.debug("webloginlog; Got nonce: \(nonceValue!.uuidString)")
                nonce = nonceValue
            } catch {
                logger.debug("webloginlog: Error fetching nonce: \(error)")
                RegistrationState.shared.isRegistrationInProgress = false

                completion(.failed)
                return
            }
            
            let nonceData = nonce!.uuidString.lowercased().data(using: .utf8)!
            let nonceHash = SHA256.hash(data: nonceData)
            let nonceHashData = Data(nonceHash)
            
            
            let keyType = loginManager.authenticationMethod == .password ? ASAuthorizationProviderExtensionKeyType.userDeviceSigning : ASAuthorizationProviderExtensionKeyType.userSecureEnclaveKey
            
            
            let attestCertificate = try await loginManager.attestKey(ofType: keyType,  clientDataHash: nonceHashData)
            
            let attestationB64 = attestCertificate.compactMap { cert -> String? in
                guard let data = SecCertificateCopyData(cert) as Data? else { return nil }
                return data.base64EncodedString(options: [])
            }

            logger.debug("webloginlog: user attestation: \(attestationB64)")

            // POST to your registration endpoint
            guard let url = URL(string: baseURLString+"/psso/userenroll" ) else {
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
                "nonce" : nonce!.uuidString.lowercased(),
                "attestation" : attestationB64,
                "accessToken" : accessToken
            ]
            
            let jsonBody = try JSONSerialization.data(withJSONObject: params, options: [])
            request.httpBody = jsonBody
            
            
            let UrlString = url.absoluteString
            logger.debug("webloginlog: Sending user registration to \(UrlString)")
            
            URLSession.shared.dataTask(with: request) { data, response, error in
                if let httpResponse = response as? HTTPURLResponse,
                   (200...299).contains(httpResponse.statusCode) || httpResponse.statusCode == 409 {
                    completion(.success)
                    RegistrationState.shared.clear()
                    RegistrationState.shared.isRegistrationInProgress = false

                    return
                } else {
                    let responseHTTP =  response as? HTTPURLResponse
                    let code = responseHTTP?.statusCode ?? 0
                    logger.error("webloginlog: Error was \(code)")
                    logger.error("webloginlog: User Registration failed: \(error?.localizedDescription ?? "unknown")")
                    completion(.failed)
                    RegistrationState.shared.clear()
                    RegistrationState.shared.isRegistrationInProgress = false

                    return
                }
            }.resume()
            
            
            
        }
        
        
    }
    
    func registrationDidComplete() {
        
        logger.debug("webloginlog: Registration Did complete done.")

        
    }
    
    func supportedGrantTypes() -> ASAuthorizationProviderExtensionSupportedGrantTypes {
        if #available(macOS 27.0, *) {
            return [.password, .jwtBearer, .tokenExchange ]
        } else {
            return [.password, .jwtBearer]
        }
    }
    
    func protocolVersion() -> ASAuthorizationProviderExtensionPlatformSSOProtocolVersion {
        return .version2_0
        
    }
    
    func readSystemManagedPreference<T>(forKey key: String, inDomain domain: String) -> T? {
        let prefs = CFPreferencesCopyAppValue(key as CFString, domain as CFString)
        return prefs as? T
    }
    
    func profilePictureForUser(
        using loginManager: ASAuthorizationProviderExtensionLoginManager,
        completion: @escaping (Data) -> Void
    ) {
      
        logger.log("webloginlog: Getting profile picture of the user")
        let claimName = (loginManager.extensionData["ProfilePictureURLClaim"] as? String) ?? "picture"
                        
        guard
             let idToken = loginManager.ssoTokens?["id_token"] as? String,
             let claims = decodeJWT(idToken),
             !claimName.isEmpty,
             let urlString = claims[claimName] as? String,
             let url = URL(string: urlString)
             
        else {
             
             logger.error("webloginlog: No picture to synchronize. No claim found.")
             returnPicture(with: Data(), completion: completion)
             //completion(Data())
             return
            }
             
        var request = URLRequest(url: url)


        URLSession.shared.dataTask(with: request) { data, response, error in

            guard
                error == nil,
                let http = response as? HTTPURLResponse,
                (200..<300).contains(http.statusCode),
                let data
            else {
                logger.error("webloginlog: Error downloading profile picture")
                self.returnPicture(with: Data(), completion: completion)
                //completion(Data())
                return
            }

            // JPEG magic number (FF D8 FF)
            if data.starts(with: [0xFF, 0xD8, 0xFF]) {
                logger.log("webloginlog: JPEG picture found.")
                self.returnPicture(with: data, completion: completion)
                //completion(data)
                return
            }

            guard
                let image = NSImage(data: data),
                let jpegData = image.jpegData()
            else {
                logger.error("webloginlog: Picture couldn't be converted.")
                self.returnPicture(with: Data(), completion: completion)
                //completion(Data())
                return
            }
            logger.log("webloginlog: profile picture successfully converted to JPEG.")

            
            self.returnPicture(with: jpegData, completion: completion)

        }.resume()
    }
 
    func returnPicture(with data: Data, completion: @escaping (Data) -> Void) {
        DispatchQueue.main.async {
            completion(data)
        }
    }
    
    func doSilentUserRegistration(refresh_token: String, loginManager: ASAuthorizationProviderExtensionLoginManager){
        
        let base_url = loginManager.extensionData["BaseURL"] as? String ?? "fallback-baseURL"
        let clientID  = loginManager.extensionData["ClientID"] as? String ?? "psso"
        
        let url = URL(string: "\(base_url)/protocol/openid-connect/token")!
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "refresh_token": refresh_token,
            "grant_type" : "refresh_token",
            "client_id" : clientID
        ]

        request.httpBody = body
            .map { "\($0.key)=\(($0.value as AnyObject).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
                .joined(separator: "&")
                .data(using: .utf8)
        
        
        URLSession.shared.dataTask(with: request) { data, response, error in

                if let error = error {
                    logger.error("webloginlog: Error on HTTP request for access token: \(error.localizedDescription).")
                    self.idpLogin(isSetupAssistant: true, loginManager: loginManager)
                    return
                }

                guard let httpResponse = response as? HTTPURLResponse else {
                   logger.error("webloginlog: Response was not successfull.")
                   self.idpLogin(isSetupAssistant: true, loginManager: loginManager)
                   return
               }
                guard let data = data else {
                    logger.error("webloginlog: no data returned from access token request.")
                    self.idpLogin(isSetupAssistant: true, loginManager: loginManager)
                    return
                }

                do {
                    let newData = String(decoding: data, as: UTF8.self)
                    
                    guard
                            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                            let accessToken = json["access_token"] as? String,
                            let access_token = self.decodeJWT(accessToken),
                            let idpUsername = access_token["preferred_username"] as? String
                                
                        else {
                            logger.log("webloginlog: Token response did not contain an access_token.")
                            self.idpLogin(isSetupAssistant: true, loginManager: loginManager)
                        
                            return
                        }

                    RegistrationState.shared.idpUsername = idpUsername
                    self.registerUser(accessToken: accessToken )
                    return
                    
                } catch {
                    logger.error("webloginlog: Error decoding access token: \(error.localizedDescription).")
                    self.idpLogin(isSetupAssistant: true, loginManager: loginManager)
                    return

                }

            }.resume()
        
    }
    
    func keyWillRotate(for keyType: ASAuthorizationProviderExtensionKeyType, newKey: SecKey, loginManager: ASAuthorizationProviderExtensionLoginManager) async -> Bool {
        logger.log("weblogin: keyWillRotate called for keyType \(keyType.rawValue)")

        // Our registration flow (see registerDevice/registerUser) needs a fresh
        // access token to attest and post the new public keys to the IdP, which we
        // don't have in this callback. So instead of completing the rotation in
        // place, we decline it and ask the OS to re-run the relevant registration,
        // which re-establishes the keys through the normal token-backed flow.
        switch keyType {
        case .userDeviceSigning, .userDeviceEncryption, .userSecureEnclaveKey, .userSmartCard:
            logger.log("weblogin: keyWillRotate - requesting user registration repair")
            loginManager.userRegistrationsNeedsRepair()
        case .sharedDeviceSigning, .sharedDeviceEncryption, .currentDeviceSigning, .currentDeviceEncryption:
            logger.log("weblogin: keyWillRotate - requesting device registration repair")
            loginManager.deviceRegistrationsNeedsRepair()
        @unknown default:
            logger.error("weblogin: keyWillRotate - unknown keyType \(keyType.rawValue), declining rotation")
        }

        // Return false: we did not rotate to newKey ourselves; a full repair will run instead.
        return false
    }
}




