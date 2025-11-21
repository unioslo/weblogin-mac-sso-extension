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


private let kService = "Weblogin SSO Session Cache"
let logger = Logger(subsystem: "no.uio.WebloginSSO", category: "general")

class AuthenticationViewController: NSViewController, WKNavigationDelegate  {
    
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
        var signedRefreshToken: String?
        var baseURL = ""

    private var mdmConfig: (baseURL: String, issuer: String, clientID: String, audience: String)?


    
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
        guard let baseURL = self.mdmConfig?.baseURL else {
            return
        }
        self.baseURL = baseURL
        // Overlay config
        
        
        // Create overlay
            overlayView = NSView()
            overlayView.wantsLayer = true
            overlayView.layer?.backgroundColor = NSColor(calibratedWhite: 0, alpha: 0.35).cgColor
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
        
        
        
    }
    override func viewDidAppear() {
        _ = self.view
        
        if (!RegistrationState.shared.isRegistrationInProgress){
            logger.debug("webloginlog: viewDidAppear called.")
            if let url = url {
                logger.debug("webloginlog: viewDidAppear. The url is: \(url.absoluteString)")
                webView.navigationDelegate=self
                var request = URLRequest(url: url)
                let cookies = getCookies()
                
                // We don't handle cookies anymore
              //  if let cookies = cookies {
                   // logger.log("webloginlog: Cookies are saved.")
                  //  request.setValue(self.combineCookies(cookies: cookies), forHTTPHeaderField: "Cookie")
                    
                //    }
                if let signedRefreshToken {
                    logger.debug("webloginlog: Signed token being sent to Keycloak")
                    request.setValue("Bearer \(signedRefreshToken)", forHTTPHeaderField: "Platform-SSO-Authorization")
                }
                //request.httpShouldHandleCookies=true
            
                webView.configuration.allowsInlinePredictions = true
                webView.load(request)
            }
            isMainViewHidden = true
            view.isHidden = true
            // view.window?.setContentSize(NSMakeSize(820, 600))
        }
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
        
        
        guard let mdmConfig else {
            logger.error("webloginlog: No MDM config, aborting")
            authorizationRequest?.complete(error: ASAuthorizationError(.canceled))
            return
            
        }
        
        let baseURL = URL(string: mdmConfig.baseURL)!
        let authorizationURLs = [ "\(baseURL)/protocol/openid-connect/auth", "\(baseURL)/protocol/saml?SAMLRequest"]
        
        var startAuthorization = false
        logger.debug("webloginlog: Request absolute string \(request.url.absoluteURL.absoluteString)")
        for authorizationURL in authorizationURLs {
            
            logger.info("webloginlog: checking authorization url: \(authorizationURL)")
            if request.url.absoluteURL.absoluteString.starts(with: authorizationURL) {
                logger.debug("webloginlog: beginning authorization url: \(authorizationURL)")
                
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
            authorizationRequest?.doNotHandle()
            return
        }
        
        let loginManager = request.loginManager
        let tokens = loginManager?.ssoTokens
     
    /*
        if let tokens {
            for token in tokens {
                let name = token.key as? String
                    let value = token.value as? String? ?? "nil"
                }
            }
     */
        if let loginManager = loginManager {
            if (loginManager.isDeviceRegistered && loginManager.isUserRegistered)
            {
                
                
                
                if let value = tokens?[AnyHashable("refresh_token")] as? String {
                    if let refreshToken = loginManager.ssoTokens?["refresh_token"]{
                        let signedToken = signToken(token: refreshToken as! String, loginManager: loginManager)
                        self.signedRefreshToken = signedToken
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
            logger.debug("webloginlog: Headers: \(String(describing: headers))")
        }
        
        url=request.url
        logger.debug("webloginlog: beginAuthorization. The request url is: \(request.url.absoluteString)")
        
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
        
    }
    
    
    func signToken(token: String, loginManager: ASAuthorizationProviderExtensionLoginManager) -> String? {
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
        
        let envelope: [String: Any] = [
            "refresh_token": token,
            "kid": signKeyId,
            "signed_at": now,
            "username" : username
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
        
    
    
    
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard  let webViewURL = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }
        logger.debug("webloginlog: Entering decision policy for: \(webViewURL.absoluteString)")
        
        // Handle required actions in Keycloak
        
        let requiredActionUrl = "\(self.baseURL)/login-actions/required-action"
        let loginActionUrl = "\(self.baseURL)/login-actions/"
        
        if (RegistrationState.shared.isRegistrationInProgress){
            logger.debug( "webloginlog: Registration login flow.")

            if webViewURL.absoluteString.starts(with: "weblogin-sso://idp-login-redirect"){
                logger.debug( "webloginlog: Login successful. URL: \(webViewURL.absoluteString)")
                var hasCode = false
                if let components = URLComponents(url: webViewURL, resolvingAgainstBaseURL: false)  {
                    let code =  components.queryItems?.first(where: { $0.name == "code" })?.value
                    logger.debug("webloginlog: Code is: \(code ?? "nil")")

                    if code != nil {
                        hasCode = true
                        /*
                        self.isMainViewHidden = true
                        self.view.isHidden = true
                        //self.webView.isHidden = true
                        self.view.needsLayout = false
                        self.view.layoutSubtreeIfNeeded()
                         */
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
                self.authorizationRequest?.doNotHandle()
                return
                
            }else {
                
                decisionHandler(.allow)
            }
            return
        }
       
        logger.debug("webloginlog: Navigation to: \(webViewURL.absoluteString)")
        guard let request = navigationAction.request as? NSMutableURLRequest, let url = url else {
            decisionHandler(.allow)
            return
            
        }
        
        
        if showedInteractiveLogin { self.view.isHidden = false }
    
        // Here we handle SAML authentication
        // The difference is that there's no callback, so we detect
        // the referer. When the IDP returns to the referer
        // and a POST is done, here's the SAML request being posted.
        if (self.saml){
            logger.debug("webloginlog: This is a SAML authentication.")
            if (is_post){ // final step, we return to the browser with
                //this redirection
                post_done = true
               
                decisionHandler(.allow)
                logger.debug("webloginlog: We cancel the navigation and return")
                self.postHeaders["Location"] = webViewURL.absoluteString
                if let response = HTTPURLResponse(url: url, statusCode: 303, httpVersion: nil, headerFields: self.postHeaders) {
                        
                        logger.debug("webloginlog: Saved cookies, redirecting to:  \(webViewURL.absoluteString)")
                        self.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                    }else {
                        logger.debug("webloginlog: We couldn't send the user back!")
                        
                    }
                    
                    return
                
            }
         
            if (request.httpMethod == "POST" && webViewURL.absoluteString.starts(with: (kCallbackURLString) )){
                logger.debug("webloginlog: POST request - let it finish")
                is_post = true
                decisionHandler(.allow)
                
                webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                    self.postHeaders = [
                            "Location": webViewURL.absoluteString,
                            "Set-Cookie": self.combineCookies(cookies: cookies)
                        ]
                        self.storeCookies(cookies)
                   
                    
                        
                    }
                 
                return
                
            }
            decisionHandler(.allow)
            return
        }
        else {
            logger.debug("webloginlog: Not a SAML request. ")
        }
        
        logger.debug("webloginlog: the URL is \(webViewURL.absoluteString) ")
        // Intercept redirect back to app callback
        
        let components = URLComponents(url: webViewURL, resolvingAgainstBaseURL: false)
        let code =  components?.queryItems?.first(where: { $0.name == "code" })?.value
        
        // needs fixing
        if webViewURL.absoluteString.starts(with: kCallbackURLString)  {
       
        logger.debug("webloginlog: Intercepted callback redirect: \(webViewURL.absoluteString)")

            // Stop navigation
           
            logger.debug("webloginlog: Handling it as OIDC")
            decisionHandler(.cancel)
            
     
            
            // Extract cookies
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
               
                let headers: [String:String] = [
                    "Location": webViewURL.absoluteString,
                    "Set-Cookie": self.combineCookies(cookies: cookies)
                ]
                
           
                    if let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: headers) {
                        
                        logger.debug("webloginlog: Sending redirect response to browser from intercepted: \(webViewURL.absoluteString)")
                        self.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
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
        
        logger.debug("webloginlog: Entering Server redirection for: \(webViewURL.absoluteString)")

        if (RegistrationState.shared.isRegistrationInProgress){
            
            return
        }
 
        if (webViewURL.absoluteString.starts(with: (kCallbackURLString))) {
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies({ cookies in
                
                let headers: [String:String] = [
                    "Location": webViewURL.absoluteString,
                    "Set-Cookie": self.combineCookies(cookies: cookies)
                ]
                 
                    // webView.configuration.websiteDataStore.
              // let headers: [String:String] = [:]
             
               
         //       self.storeCookies(cookies)
               
                    if let response = HTTPURLResponse.init(url: url, statusCode: 303, httpVersion: nil, headerFields: headers) {
                        logger.debug("webloginlog: we send the redirect to the browser: \(url.absoluteString)")
                        self.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                    }else {
                        logger.error("webloginlog: Failed to construct HTTPURLResponse.")
                    }
                
            })
           
        }
        
        
    
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        logger.debug("webloginlog: finished loading")
        let webViewURL = webView.url!
        guard firstResponseChecked == false else { return }
        if (RegistrationState.shared.isRegistrationInProgress){
            return
        }
        
        if (!firstResponseChecked){
            firstResponseChecked = true
            logger.debug("webloginlog: First response")
            
            // Run a minimal DOM probe for a visible password input
            let js = "!!document.querySelector('input[type=\"password\"]')"
            
            webView.evaluateJavaScript(js) { [weak self] result, error in
                guard let self = self else { return }
                if let error = error {
                    logger.debug("webloginlog: First-response JS probe error: \(error.localizedDescription)")
                    return
                }
                let hasPasswordField = (result as? Bool) ?? false
                
            
                
                if (hasPasswordField ) != nil{
                    
                  // DispatchQueue.main.async {
                        if let win = self.view.window {
                                   win.makeKeyAndOrderFront(nil)
                                   // set desired content size if needed
                                   win.setContentSize(NSMakeSize(600, 550))
                               }
                    self.view.window?.makeKeyAndOrderFront(nil)
                    self.view.window?.setContentSize(NSMakeSize(600,550))
                       self.hideProcessingOverlay()
                        self.isMainViewHidden = false
                        // Don't forget to call layoutIfNeeded() when you messing with the constraints
                       // self.cancelButton.isHidden = false
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
        
        
        
    }
    
    
    
    func setupWebView() {
        self.showedInteractiveLogin = true
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
        self.timer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: false) { timer in
            logger.debug("webloginlog: more than 5 seconds without SSO - we make the web browser visible.")// Perform actions here
            self.isMainViewHidden = false
            if let win = self.view.window {
                       win.makeKeyAndOrderFront(nil)
                       // set desired content size if needed
                       win.setContentSize(NSMakeSize(600, 550))
                   }
          
            self.isMainViewHidden = false
                    // Don't forget to call layoutIfNeeded() when you messing with the constraints
           // self.cancelButton.isHidden = false
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
        let domain = "no.uio.WebloginSSO.ssoe"
        
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
        config.keyEndpointURL = URL(string: baseURL+"/psso/key")
        config.nonceResponseKeypath = "nonce"
        config.groupResponseClaimName = "groups"
        
        
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
                    win.setContentSize(NSMakeSize(600, 550))
                }
                
                webView.navigationDelegate=self
                webView.configuration.allowsInlinePredictions = true
                self.isMainViewHidden = false
                // Don't forget to call layoutIfNeeded() when you messing with the constraints
                // self.cancelButton.isHidden = false
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
            win.setContentSize(NSMakeSize(600, 550))
        }
        
        webView.navigationDelegate=self
        webView.configuration.allowsInlinePredictions = true
        self.isMainViewHidden = false
        // Don't forget to call layoutIfNeeded() when you messing with the constraints
        // self.cancelButton.isHidden = false
        self.view.needsLayout = true
        self.view.layoutSubtreeIfNeeded()
        
        // Force redraw
        self.view.displayIfNeeded()
        loginManager.presentRegistrationViewController {
            result in
  
            
           self.idpLogin()
            
           // completion(.userInterfaceRequired)
                       
        
        
        }
       
    }
        
    func idpLogin() {
        logger.debug("webloginlog: Starting IdP login")

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
            // URLQueryItem(name: "login_hint", value: "francis@uio.no"),
            // URLQueryItem(name: "prompt", value: "login")
        ]

        guard let authURL = components.url else {
            logger.error("Failed to construct Keycloak auth URL")
            return
        }

        logger.debug("webloginlog: Presenting login page: \(authURL.absoluteString)")

        DispatchQueue.main.async {
            self.webView.navigationDelegate = self
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
        RegistrationState.shared.accessToken = accessToken
        RegistrationState.shared.idpUsername = userName
        
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

            let params = [
                "DeviceSigningKey": signingKeyB64,
                "DeviceEncryptionKey": encryptionKeyB64,
                "SignKeyID": signKeyId,
                "EncKeyID": encKeyId,
                "nonce" : nonce!.uuidString.lowercased(),
                "attestation" : attestationB64,
                "accessToken" : accessToken
            
        ]

            let jsonBody = try JSONSerialization.data(withJSONObject: params, options: [])
            request.httpBody = jsonBody
            
            let UrlString = url.absoluteString
            logger.debug("webloginlog: Sending registration to \(UrlString)")

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
        
        loginManager.resetUserSecureEnclaveKey()
        guard let userKey = loginManager.key(for: .userSecureEnclaveKey)
            else {
                logger.error("webloginlog: Failed to get user key.")
                completion(.failed)
                return
        }
        guard let userName = RegistrationState.shared.idpUsername else {
             logger.error("webloginlog: No username found.")
             completion(.failed)
             return
         }
        
        guard let config = loginManager.userLoginConfiguration else {
            logger.error("webloginlog: Failed to get user login configuration.")
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
      
        do {
            try loginManager.saveUserLoginConfiguration(config)

       }catch{
       
           logger.error("webloginlog: Failed to save the configuration \(error).")
           completion(.failed)
       }

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
            let attestCertificate = try await loginManager.attestKey(ofType: .userSecureEnclaveKey,  clientDataHash: nonceHashData)
            
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


private extension AuthenticationViewController {
    
    func stringFromManagedPreferences(forKey key: String, inDomain domain: String) -> String? {
        guard let value = CFPreferencesCopyAppValue(key as CFString, domain as CFString) else {
            return nil
        }
        return value as? String
    }
    
    func loadMDMConfig() {
        let domain = "no.uio.WebloginSSO.ssoe"
        
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
    
        
    func keyIdentifier(for key: SecKey) -> String? {
        guard let pubKey = SecKeyCopyPublicKey(key),
              let data = SecKeyCopyExternalRepresentation(pubKey, nil) as Data? else {
            return nil
        }
        let digest = SHA256.hash(data: data)
        return digest.compactMap { String(format: "%02x", $0) }.joined()
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
        
    
    func exchangeCodeForToken(code: String) async throws -> TokenResponse {
        guard let baseURL = self.mdmConfig?.baseURL else { throw URLError(.badURL) }
        guard let clientId = self.mdmConfig?.clientID else { throw URLError(.badURL)}
        let url = URL(string: "\(baseURL)/protocol/openid-connect/token")!
        var request = URLRequest(url: url)
        
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let verifier = RegistrationState.shared.pkceVerifier ?? ""
        let body = "grant_type=authorization_code&code=\(code)&redirect_uri=weblogin-sso://idp-login-redirect&client_id=\(clientId)&code_verifier=\(verifier)"
        request.httpBody = body.data(using: .utf8)

        let (data, _) = try await URLSession.shared.data(for: request)
        do {
            let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]


            if let json = json {
                for (key, value) in json {
                    logger.debug("webloginlog: \(key): \(String(describing: value))")
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

    struct TokenResponse: Codable {
        let access_token: String
        let refresh_token: String
        let id_token: String
        let expires_in: Int
    }

    
    
    struct Nonce: Decodable {
            let nonce: UUID
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

    func showProcessingOverlay() {
        overlayView.isHidden = false
        spinner.startAnimation(nil)
    }
    func hideProcessingOverlay() {
        overlayView.isHidden = true
        spinner.stopAnimation(nil)
    }
}
