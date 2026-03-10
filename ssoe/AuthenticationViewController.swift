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
        loadMDMConfig()
        
   
        
  
        
        logger.log("webloginlog: viewDidLoad")
        guard let baseURL = self.mdmConfig?.baseURL else {
            return
        }

                
        
        self.baseURL = baseURL
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


        
    }
    override func viewDidAppear() {
        _ = self.view
       


        
        if (!RegistrationState.shared.isRegistrationInProgress){
            logger.info("webloginlog: viewDidAppear called.")
        

            }
            isMainViewHidden = true
            view.isHidden = true
            // view.window?.setContentSize(NSMakeSize(820, 600))
        
    }

    override var nibName: NSNib.Name? {
        return NSNib.Name("AuthenticationViewController")
        }
}


extension AuthenticationViewController: ASAuthorizationProviderExtensionAuthorizationRequestHandler {
    
   
            
    public func beginAuthorization(with request: ASAuthorizationProviderExtensionAuthorizationRequest) {
        self.authorizationRequest = request
        self.firstResponseChecked = false
        self.showedInteractiveLogin = false
        webView.configuration.userContentController.add(self, name: "pssoStepUp")
        
        let sharedDefaults = UserDefaults(suiteName: "group.no.uio.weblogin")
        let disableSSO = sharedDefaults?.bool(forKey: "disable_sso") ?? false
        
        logger.log("webloginlog: is sso disabled? \(disableSSO)")
        
        if disableSSO {
            logger.info("webloginlog: Disabling SSO, aborting")
            webView.configuration.userContentController.removeAllScriptMessageHandlers()
            authorizationRequest?.doNotHandle()
            return
        }
        
        
        guard let mdmConfig else {
            logger.error("webloginlog: No MDM config, aborting")
            authorizationRequest?.complete(error: ASAuthorizationError(.canceled))
            return
            
        }
        
        let baseURL = URL(string: mdmConfig.baseURL)!
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
        let tokens = loginManager?.ssoTokens
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
    
    

        
    
    
    
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard  let webViewURL = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }

     
        if (RegistrationState.shared.isRegistrationInProgress){
            logger.info( "webloginlog: Registration login flow.")
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
                        Task {

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
                return
                
            }else {
                logger.info("webloginglog: This shouldn't be shown now.")
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
            logger.info("webloginlog: Entering redirection to url starting with: \(redirectURL)")
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
        
        if let loadedURL = webViewURL.baseURL?.absoluteString {
            logger.log("webloginlog: Page starting with \(loadedURL) has been loaded.")
        }
        

        let isRequiredAction = webViewURL.absoluteString.starts(with: baseURL) && webView.url?.relativePath.contains("/login-actions") == true
        logger.log("webloginlog: this is a required action: \(isRequiredAction)")
            
        // Run a minimal DOM probe for a visible password input
        
        if webView.url?.relativePath.contains("/login-actions/required-action") == true {
            self.isRequiredAction = true
        }
        
        
        
        
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
                logger.debug("webloginlog: First-response JS probe error: \(error.localizedDescription)")
                return
            }
            
            if let dict = result as? [String: Any] {
                
                
                let hasPasswordField = dict["hasPassword"] as? Bool ?? false
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
                    
                    
                    
                    logger.debug("webloginlog: Detected interactive login on first response. Showing UI immediately.")
                } else {
                    showWindowIfDelay()
                    logger.debug("webloginlog: No password field on first response; keeping UI hidden for SSO.")
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
    
    func configuration() -> ASAuthorizationProviderExtensionLoginConfiguration {
        
        logger.debug("webloginlog: getting configuration")
        let domain = Bundle.main.bundleIdentifier ?? "no.uio.webloginSSO.ssoe"

        let clientID = CFPreferencesCopyAppValue("ClientID" as CFString, domain as CFString) as? String ?? "fallback-client"
        let baseURL  = CFPreferencesCopyAppValue("BaseURL" as CFString, domain as CFString) as? String ?? "fallback-baseURL"
        let issuer = CFPreferencesCopyAppValue("Issuer" as CFString, domain as CFString) as? String ?? "fallback-issuer"
        let audience = CFPreferencesCopyAppValue("Audience" as CFString, domain as CFString) as? String ?? "fallback-audience"
        
        
        let tokenEndpointURL = URL(string: baseURL+"/psso/token")!
        let jwksEndpointURL = URL(string: baseURL+"/protocol/openid-connect/certs")!
        
        
      
      
        
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
        
        config.refreshEndpointURL = tokenEndpointURL
        config.keyEndpointURL = tokenEndpointURL;
        config.nonceResponseKeypath = "nonce"
        config.groupResponseClaimName = "groups"
        config.audience = audience
        
        
        return config
    }
    
    func beginUserRegistration(
        loginManager: ASAuthorizationProviderExtensionLoginManager,
        userName: String?,
        method authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod,
        options: ASAuthorizationProviderExtensionRequestOptions = [],
        completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void
    ){
        
        
        logger.debug("webloginlog: is device registered? \(loginManager.isDeviceRegistered)")
        logger.info("webloginlog: Starting user registration")
        

        
        RegistrationState.shared.loginManager = loginManager
        RegistrationState.shared.registrationCompletion = completion
        RegistrationState.shared.isRegistrationInProgress = true
        RegistrationState.shared.registrationType = "user"
        let token = RegistrationState.shared.accessToken
        
        if token != nil {
            logger.debug("webloginlog: user has token. Proceeding to user registration")
            registerUser(accessToken: token!)
            
        }else {
            
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
            loginManager.presentRegistrationViewController{
                error in
                if let error = error {
                    logger.error("webloginlog: \(error)")
                    completion(.failed)
                    return
                    
                }
                
                self.idpLogin()
                
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
        
        RegistrationState.shared.loginManager = loginManager
        RegistrationState.shared.registrationCompletion = completion
        RegistrationState.shared.isRegistrationInProgress = true
        RegistrationState.shared.registrationType = "device"
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
        
        if loginManager.registrationToken == nil {
            logger.log("Device registration started using User Login.")
            loginManager.presentRegistrationViewController {
                result in
            
                
                self.idpLogin()
                
                // completion(.userInterfaceRequired)
                
                
                
            }
        }else {
            logger.log("webloginlog: Device Registration started using Registration Token.")
            registerDevice(accessToken: "", userName: "")
        }
        
    }
    
    func idpLogin() {
        logger.debug("webloginlog: Starting IdP login")
        
        RegistrationState.shared.accessToken = nil
        guard let baseURL = self.mdmConfig?.baseURL,
              let clientID = self.mdmConfig?.clientID else {
            logger.error("Missing MDM baseURL or clientID")
            return
        }
        
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
            return
        }
        
        logger.debug("webloginlog: Presenting login page: \(authURL.absoluteString)")
        
        DispatchQueue.main.async {
            self.webView.navigationDelegate = self
            self.isMainViewHidden = false
            self.webView.load(URLRequest(url: authURL))
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
        
        
        let baseURL = mdmConfig?.baseURL
        
        
        do {
            let config = configuration()
            try config.setCustomLoginRequestBodyClaims( ["signKeyId": signKeyId, "encKeyId": encKeyId])
            try loginManager.saveLoginConfiguration(config)
            let savedAudience = loginManager.loginConfiguration?.audience ?? "no_audience_saved"
           
        }catch{
            let config = configuration()
            let token = config.tokenEndpointURL.absoluteString
            logger.error("webloginlog: Failed to save the configuration \(error). Token URL: \(token)")
        }
        
        var nonce = nil as UUID?
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
            
            guard let baseURL else {
                logger.error("webloginlog: No baseURL found on SSO Extension profile from MDM.")
                completion(.failed)
                return
            }
            
            // POST to your registration endpoint
            guard let url = URL(string: baseURL+"/psso/enroll" ) else {
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
            
            var params = [
                "DeviceSigningKey": signingKeyB64,
                "DeviceEncryptionKey": encryptionKeyB64,
                "SignKeyID": signKeyId,
                "EncKeyID": encKeyId,
                "nonce" : nonce!.uuidString.lowercased(),
                "attestation" : attestationB64,
            ]
            
            if loginManager.registrationToken != nil {
                params["registrationToken"] = loginManager.registrationToken
                
            } else {
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
                    logger.error("webloginlog: Registration failed: \(error?.localizedDescription ?? "unknown")")
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
            return }
        
        guard let userName =
                RegistrationState.shared.idpUsername else {
            logger.error("webloginlog: No username found.")
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
            completion(.failed)
        }
        
        if loginManager.authenticationMethod == .password {
            let audience = loginManager.loginConfiguration?.audience
            
            logger.log("webloginlog: The audience in user registration is: \(audience as NSObject?)")
            let userDeviceSigning = loginManager.key(for: .userDeviceSigning)
            
            completion(.success)
            return
        }
        
     
        loginManager.resetUserSecureEnclaveKey()
        guard let userKey = loginManager.key(for: .userSecureEnclaveKey) else {
            logger.error("webloginlog: No user key found.")
            completion(.failed)
            return
        }
            let baseURL = mdmConfig?.baseURL
            guard let userPublicKey = SecKeyCopyPublicKey(userKey) else {
                logger.error("webloginlog: Can't export the public key for the user.")
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
            
            
            let attestCertificate = try await loginManager.attestKey(ofType: keyType,  clientDataHash: nonceHashData)
            
            let attestationB64 = attestCertificate.compactMap { cert -> String? in
                guard let data = SecCertificateCopyData(cert) as Data? else { return nil }
                return data.base64EncodedString(options: [])
            }
            
            logger.debug("webloginlog: user attestation: \(attestationB64)")
            guard let baseURL else {
                logger.error("webloginlog: No baseURL found on SSO Extension profile from MDM.")
                completion(.failed)
                return
            }
            
            // POST to your registration endpoint
            guard let url = URL(string: baseURL+"/psso/userenroll" ) else {
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
                    return
                } else {
                    let responseHTTP =  response as? HTTPURLResponse
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
    
    func registrationDidComplete() {
        
        logger.debug("webloginlog: Registration Did complete done.")
        
    }
    
    func supportedGrantTypes() -> ASAuthorizationProviderExtensionSupportedGrantTypes {
        return [.password, .jwtBearer]
    }
    
    func protocolVersion() -> ASAuthorizationProviderExtensionPlatformSSOProtocolVersion {
        return .version2_0
        
    }
    
    func readSystemManagedPreference<T>(forKey key: String, inDomain domain: String) -> T? {
        let prefs = CFPreferencesCopyAppValue(key as CFString, domain as CFString)
        return prefs as? T
    }
    
}


