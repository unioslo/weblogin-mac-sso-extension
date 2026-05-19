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
import LocalAuthentication

class AuthenticationViewController: NSViewController, WKNavigationDelegate {

    // Handlers
    let registrationHandler = RegistrationHandler()
    let authorizationHandler = AuthorizationHandler()

    // UI Elements
    var overlayView: NSView!
    var spinner: NSProgressIndicator!
    var overlayLabel: NSTextField!

    @IBOutlet weak var webView: WKWebView!
    @IBOutlet weak var cancelButton: NSButton!

    // State for webView navigation (used by AuthorizationHandler)
    var hiddenHeightConstraint: NSLayoutConstraint?
    var showingHeightConstraint: NSLayoutConstraint?
    var isDeviceRegistrationFlow: Bool = false
    var isMainViewHidden: Bool = false {
        didSet {
            view.isHidden = isMainViewHidden
            hiddenHeightConstraint?.isActive = isMainViewHidden
            showingHeightConstraint?.isActive = !isMainViewHidden
            view.layer?.setNeedsLayout()
        }
    }
    var timer: Timer?
    var registrationWebView: WKWebView?

    @IBAction func cancelButtonPressed(_ sender: Any) {
        if isDeviceRegistrationFlow {
            RegistrationState.shared.registrationCompletion?(.failed)
            RegistrationState.shared.clear()
        }
        authorizationHandler.authorizationRequest?.doNotHandle()
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        // Set up handlers
        registrationHandler.viewController = self
        authorizationHandler.viewController = self

        logger.log("webloginlog: viewDidLoad")

        guard let baseURL = registrationHandler.mdmConfig?.baseURL else {
            return
        }

        // Create overlay
        overlayView = NSView()
        overlayView.wantsLayer = true
        overlayView.layer?.backgroundColor = NSColor(calibratedWhite: 0, alpha: 0.75).cgColor
        overlayView.isHidden = true
        overlayView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(overlayView)

        NSLayoutConstraint.activate([
            overlayView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            overlayView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            overlayView.topAnchor.constraint(equalTo: view.topAnchor),
            overlayView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])

        spinner = NSProgressIndicator()
        spinner.style = .spinning
        spinner.controlSize = .large
        spinner.isIndeterminate = true
        spinner.startAnimation(nil)
        spinner.appearance = NSAppearance(named: .darkAqua) ?? NSAppearance()
        spinner.translatesAutoresizingMaskIntoConstraints = false
        overlayView.addSubview(spinner)

        overlayLabel = NSTextField(labelWithString: "Registering...")
        overlayLabel.font = NSFont.systemFont(ofSize: 16, weight: .semibold)
        overlayLabel.textColor = NSColor.white
        overlayLabel.alignment = .center
        overlayLabel.translatesAutoresizingMaskIntoConstraints = false
        overlayView.addSubview(overlayLabel)

        NSLayoutConstraint.activate([
            spinner.centerXAnchor.constraint(equalTo: overlayView.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: overlayView.centerYAnchor, constant: -10),
            overlayLabel.topAnchor.constraint(equalTo: spinner.bottomAnchor, constant: 8),
            overlayLabel.centerXAnchor.constraint(equalTo: overlayView.centerXAnchor)
        ])

        webView.navigationDelegate = self
        webView.configuration.allowsInlinePredictions = true
        webView.isInspectable = true
        webView.pageZoom = 0.8
    }

    override func viewDidAppear() {
        _ = self.view

        if !RegistrationState.shared.isRegistrationInProgress {
            logger.info("webloginlog: viewDidAppear called.")
        }

        isMainViewHidden = true
        view.isHidden = true
    }

    override var nibName: NSNib.Name? {
        return NSNib.Name("AuthenticationViewController")
    }

    func showProcessingOverlay() {
        overlayView.isHidden = false
        spinner.startAnimation(nil)
    }

    func hideProcessingOverlay() {
        overlayView.isHidden = true
        spinner.stopAnimation(nil)
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

    func showWindowIfDelay() {
        self.timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: false) { timer in
            logger.debug("webloginlog: more than 5 seconds without SSO - we make the web browser visible.")
            self.isMainViewHidden = false
            if let win = self.view.window {
                win.makeKeyAndOrderFront(nil)
                win.setContentSize(NSMakeSize(700, 560))
            }

            self.isMainViewHidden = false
            self.view.alphaValue = 1.0
            self.view.window?.isOpaque = true
            self.view.needsLayout = true
            self.view.layoutSubtreeIfNeeded()
            self.view.displayIfNeeded()
        }
    }
}

// MARK: - ASAuthorizationProviderExtensionAuthorizationRequestHandler
extension AuthenticationViewController: ASAuthorizationProviderExtensionAuthorizationRequestHandler {
    func beginAuthorization(with request: ASAuthorizationProviderExtensionAuthorizationRequest) {
        authorizationHandler.beginAuthorization(with: request)
    }
}

// MARK: - ASAuthorizationProviderExtensionRegistrationHandler
extension AuthenticationViewController: ASAuthorizationProviderExtensionRegistrationHandler {

    func configuration() -> ASAuthorizationProviderExtensionLoginConfiguration {
        return registrationHandler.configuration()
    }

    func beginDeviceRegistration(
        loginManager: ASAuthorizationProviderExtensionLoginManager,
        options: ASAuthorizationProviderExtensionRequestOptions = [],
        completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void
    ) {
        registrationHandler.beginDeviceRegistration(loginManager: loginManager, options: options, completion: completion)
    }

    func beginUserRegistration(
        loginManager: ASAuthorizationProviderExtensionLoginManager,
        userName: String?,
        method authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod,
        options: ASAuthorizationProviderExtensionRequestOptions = [],
        completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void
    ) {
        registrationHandler.beginUserRegistration(
            loginManager: loginManager,
            userName: userName,
            method: authenticationMethod,
            options: options,
            completion: completion
        )
    }

    func registrationDidComplete() {
        registrationHandler.registrationDidComplete()
    }

    func supportedGrantTypes() -> ASAuthorizationProviderExtensionSupportedGrantTypes {
        return registrationHandler.supportedGrantTypes()
    }

    func protocolVersion() -> ASAuthorizationProviderExtensionPlatformSSOProtocolVersion {
        return registrationHandler.protocolVersion()
    }
}

// MARK: - WKScriptMessageHandler
extension AuthenticationViewController: WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "pssoStepUp" else { return }
        logger.log("webloginlog: Got a JS message.")

        guard let body = message.body as? [String: Any] else { return }

        if let type = body["type"] as? String, type == "getSignedToken" {
            handleStepUpRequest { error in
                if let error = error {
                    logger.log("webloginlog: Reauthentication failed: \(error)")
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                        self.sendSignedTokenToJS("none")
                    }
                    return
                }

                Task { @MainActor in
                    logger.log("webloginlog: Sending signed token to the IdP via javascript")

                    guard let tokens = self.authorizationHandler.loginManager?.ssoTokens else {
                        logger.error("webloginlog: No SSO tokens available")
                        self.sendSignedTokenToJS("none")
                        return
                    }

                    // Log what tokens are available
                    logger.debug("webloginlog: Available token keys: \(tokens.keys)")

                    var tokenType = ""
                    if let _ = tokens[AnyHashable("refresh_token_expires_in")] as? Int {
                        tokenType = "refresh_token"
                        logger.log("webloginlog: Using refresh_token for signing")
                    } else {
                        tokenType = "id_token"
                        logger.log("webloginlog: Using id_token for signing")
                    }

                    let clientId = UUID().uuidString

                    guard let nonce = try? await self.authorizationHandler.getNonceFromIdp(clientRequestId: clientId) else {
                        logger.error("webloginlog: Failed to fetch nonce")
                        self.sendSignedTokenToJS("none")
                        return
                    }

                    logger.debug("webloginlog: Got nonce: \(nonce)")

                    guard let loginManager = self.authorizationHandler.loginManager,
                          let token = tokens[tokenType] as? String else {
                        logger.error("webloginlog: Missing loginManager or token for type: \(tokenType)")
                        self.sendSignedTokenToJS("none")
                        return
                    }

                    logger.debug("webloginlog: Signing token of type: \(tokenType)")

                    guard let signedToken = self.authorizationHandler.signToken(
                        token: token,
                        tokenType: tokenType,
                        loginManager: loginManager,
                        nonce: nonce,
                        clientId: clientId
                    ) else {
                        logger.error("webloginlog: Failed to sign token")
                        self.sendSignedTokenToJS("none")
                        return
                    }

                    logger.log("webloginlog: Successfully signed token, sending to JS")
                    self.authorizationHandler.signedTokenToSend = signedToken
                    self.sendSignedTokenToJS(signedToken)
                }
            }
        }
    }

    private func handleStepUpRequest(completion: @escaping ((any Error)?) -> Void) {
        if authorizationHandler.loginManager?.authenticationMethod == .password {
            self.sendSignedTokenToJS("none")
            return
        }

        self.view.isHidden = true
        self.view.window?.makeKeyAndOrderFront(nil)
        self.view.window?.setContentSize(NSMakeSize(10, 10))
        self.view.window?.isOpaque = false
        self.view.window?.backgroundColor = .clear
        self.view.layer?.backgroundColor = NSColor.clear.cgColor
        self.view.alphaValue = 0.0
        self.view.wantsLayer = true
        self.isMainViewHidden = false
        self.view.needsLayout = true
        self.webView.isHidden = false
        self.view.displayIfNeeded()
        self.view.layoutSubtreeIfNeeded()

        Task {
            view.window?.makeKeyAndOrderFront(self)
            if let policy = biometricPolicyFromExtensionData(authorizationHandler.loginManager?.extensionData ?? [:]) {
                self.authorizationHandler.loginManager?.userNeedsReauthentication { error in
                    if error != nil {
                        logger.log("webloginlog: Error with userNeedsReauthentication")
                        DispatchQueue.main.async {
                            self.sendSignedTokenToJS("none")
                            completion(error)
                        }
                        return
                    }
                    logger.info("webloginlog: User successfully reauthenticated. Proceeding with login.")
                    completion(nil)
                }
            } else {
                let ctx = LAContext()
                let localizedReason = String(localized: "authenticate you")
                ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: localizedReason) { success, error in
                    logger.log("webloginlog: User asked for reauthentication. Success: \(success)")

                    if success != true {
                        logger.log("webloginlog: User didn't approve login. Returning.")
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                            self.sendSignedTokenToJS("none")
                        }
                        return
                    }

                    logger.log("webloginlog: Calling userNeedsReauthentication")
                    self.authorizationHandler.loginManager?.userNeedsReauthentication { error in
                        if error != nil {
                            logger.log("webloginlog: Error with userNeedsReauthentication")
                            DispatchQueue.main.async {
                                self.sendSignedTokenToJS("none")
                                completion(error)
                            }
                            return
                        }
                        logger.info("webloginlog: User successfully reauthenticated. Proceeding with login.")
                        completion(nil)
                    }
                }
            }
        }
    }

    func sendSignedTokenToJS(_ signedToken: String) {
        logger.log("webloginlog: sendSignedTokenToJS called with token: \(signedToken.prefix(20))...\(signedToken.suffix(20))")

        DispatchQueue.main.async {
            // First check if pssoSigned function exists
            let checkJS = "typeof pssoSigned === 'function'"
            self.webView.evaluateJavaScript(checkJS) { result, error in
                if let exists = result as? Bool, exists {
                    logger.log("webloginlog: pssoSigned function exists on page")
                } else {
                    logger.error("webloginlog: pssoSigned function does NOT exist on page!")
                }

                // Call the function regardless, to see the error if it fails
                let js = "pssoSigned('\(signedToken)');"
                self.webView.evaluateJavaScript(js) { result, error in
                    if let error = error {
                        logger.error("webloginlog: Error calling pssoSigned: \(error.localizedDescription)")
                    } else {
                        logger.log("webloginlog: pssoSigned JavaScript executed successfully, result: \(String(describing: result))")
                    }
                }
            }
        }
    }
}
