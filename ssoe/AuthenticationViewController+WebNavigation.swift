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

import WebKit
import AuthenticationServices

// MARK: - WKNavigationDelegate Implementation
extension AuthenticationViewController {

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let webViewURL = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }

        // Skip registration flows - they're handled by ASWebAuthenticationSession
        if RegistrationState.shared.isRegistrationInProgress {
            decisionHandler(.cancel)
            logger.log("webloginlog: Registration login flow.")
            return
        }

        guard let request = navigationAction.request as? NSMutableURLRequest,
              let url = authorizationHandler.url else {
            decisionHandler(.allow)
            return
        }

        // SAML handling
        if authorizationHandler.saml {
            logger.debug("webloginlog: Handling SAML request")

            var containsSAMLResponse: Bool = false
            var httpBody: String? = ""
            if let httpBodyData = request.httpBody {
                httpBody = String(data: httpBodyData, encoding: .utf8)
                containsSAMLResponse = httpBody!.contains("SAMLResponse")
                logger.debug("webloginlog: Contains SAML Response: \(containsSAMLResponse)")
            }

            let idpURL = url.absoluteString.starts(with: authorizationHandler.mdmConfig?.baseURL ?? "")
            let components = URLComponents(url: webViewURL, resolvingAgainstBaseURL: false)
            let samlResponse = components?.queryItems?.first(where: { $0.name == "SAMLResponse" })?.value

            // SAML REDIRECT
            if idpURL == true && samlResponse != nil {
                logger.debug("webloginlog: This is a SAML Redirect flow.")
                decisionHandler(.cancel)
                webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                    let postHeaders = [
                        "Location": webViewURL.absoluteString,
                        "Set-Cookie": combineCookies(cookies: cookies),
                        "Content-Type": "text/html; charset=utf-8"
                    ]
                    let httpVersion = "HTTP/1.1"
                    if let response = HTTPURLResponse(url: url, statusCode: 303, httpVersion: httpVersion, headerFields: postHeaders) {
                        webView.configuration.userContentController.removeAllScriptMessageHandlers()
                        self.authorizationHandler.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                        return
                    }
                }
                return
            }

            let httpMethod = request.httpMethod
            logger.debug("webloginlog: HttpMethod: \(httpMethod)")

            // SAML POST
            if request.httpMethod == "POST" && idpURL == true && containsSAMLResponse == true {
                authorizationHandler.is_post = true
                decisionHandler(.cancel)
                var html = """
                        <html>
                        <body onload="document.forms[0].submit()">
                        <form action="\(webViewURL.absoluteString)" method="post">

                        """
                let saml_response = httpBody!.split(separator: "&")

                for param in saml_response {
                    let key_value = param.split(separator: "=", maxSplits: 1)
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
                    let postHeaders = [
                        "Set-Cookie": combineCookies(cookies: cookies),
                        "Content-Type": "text/html; charset=utf-8"
                    ]
                    let httpVersion = "HTTP/1.1"
                    if let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: httpVersion, headerFields: postHeaders) {
                        let data = theForm.data(using: .utf8)
                        webView.configuration.userContentController.removeAllScriptMessageHandlers()
                        self.authorizationHandler.authorizationRequest?.complete(httpResponse: response, httpBody: data)
                        return
                    }
                }
                return
            }
            decisionHandler(.allow)
            return
        } else {
            logger.debug("webloginlog: Not a SAML request.")
        }

        // Handle callback URL
        if webViewURL.absoluteString.starts(with: authorizationHandler.kCallbackURLString) {
            logger.debug("webloginlog: Intercepted redirect to callback. Send it to the browser.")

            if authorizationHandler.saml == true {
                decisionHandler(.allow)
                return
            }

            decisionHandler(.cancel)

            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                let headers: [String: String] = [
                    "Location": webViewURL.absoluteString,
                    "Set-Cookie": combineCookies(cookies: cookies)
                ]

                if let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: headers) {
                    logger.debug("webloginlog: Sending redirect response to browser from intercepted url.")
                    webView.configuration.userContentController.removeAllScriptMessageHandlers()
                    self.authorizationHandler.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                    return
                } else {
                    logger.error("webloginlog: Failed to construct HTTPURLResponse for oidc.")
                }
            }

            return
        }

        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
        guard let url = authorizationHandler.url, let webViewURL = webView.url else {
            return
        }

        if let redirectURL = webViewURL.baseURL?.absoluteString {
            logger.log("webloginlog: Entering redirection to url starting with: \(redirectURL)")
        }

        if RegistrationState.shared.isRegistrationInProgress {
            return
        }

        if webViewURL.absoluteString.starts(with: authorizationHandler.kCallbackURLString) {
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies({ cookies in
                let headers: [String: String] = [
                    "Location": webViewURL.absoluteString,
                    "Set-Cookie": combineCookies(cookies: cookies)
                ]

                if webViewURL.absoluteString.starts(with: self.authorizationHandler.mdmConfig?.baseURL ?? "") && self.authorizationHandler.saml == true {
                    logger.log("webloginlog: redirecting to the idp. continue on the webview.")
                    return
                }

                if let response = HTTPURLResponse.init(url: url, statusCode: 302, httpVersion: nil, headerFields: headers) {
                    webView.configuration.userContentController.removeAllScriptMessageHandlers()
                    self.authorizationHandler.authorizationRequest?.complete(httpResponse: response, httpBody: nil)
                } else {
                    logger.error("webloginlog: Failed to construct HTTPURLResponse.")
                }
            })
        } else {
            logger.log("webloginlog: not the callback redirection. continue")
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if RegistrationState.shared.isRegistrationInProgress {
            return
        }

        guard let webViewURL = webView.url else {
            logger.error("webloginlog: I don't have an url, or the webview doesn't have one")
            return
        }

        let baseURL = authorizationHandler.mdmConfig?.baseURL ?? ""
        let isRequiredAction = webViewURL.absoluteString.starts(with: baseURL) && webView.url?.relativePath.contains("/login-actions") == true
        logger.log("webloginlog: this is a required action: \(isRequiredAction)")

        if webView.url?.relativePath.contains("/login-actions/required-action") == true {
            authorizationHandler.isRequiredAction = true
        }
        logger.log("webloginlog: this is a required action: \(isRequiredAction)")

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
                    return
                }

                logger.debug("webloginlog: the form has a password field: \(hasPasswordField)")
                logger.debug("webloginlog: is post \(self.authorizationHandler.is_post)")

                if ((self.authorizationHandler.saml == false && hasPasswordField == true) ||
                    (self.authorizationHandler.saml == true && self.authorizationHandler.is_post != true && hasPasswordField == true) ||
                    (isRequiredAction == true && self.authorizationHandler.is_post != true)) &&
                    !self.authorizationHandler.postSaml {

                    self.authorizationHandler.postSaml = false
                    if let win = self.view.window {
                        win.makeKeyAndOrderFront(nil)
                        win.setContentSize(NSMakeSize(700, 560))
                    }
                    self.view.window?.makeKeyAndOrderFront(nil)
                    self.view.window?.setContentSize(NSMakeSize(700, 560))
                    self.hideProcessingOverlay()
                    self.isMainViewHidden = false
                    self.view.alphaValue = 1.0
                    self.view.window?.isOpaque = true
                    self.view.needsLayout = true
                    self.webView.isHidden = false
                    self.view.displayIfNeeded()
                    self.view.isHidden = false
                    self.view.layoutSubtreeIfNeeded()

                    logger.log("webloginlog: Detected interactive login on first response. Showing UI immediately.")
                } else {
                    self.showWindowIfDelay()
                    logger.log("webloginlog: No password field on first response; keeping UI hidden for SSO.")
                }
            }
        }
    }
}
