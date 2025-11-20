//
//  ViewController.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 22/10/2025.
//

import Cocoa
import WebKit
import Security

class ViewController: NSViewController {

    
    @IBAction func logoutButtonPressed(_ sender: Any) {
            clearKeychainCookies()
            clearWKWebViewSession()
            // Any other app-specific logout logic here
            print("User logged out.")
        }
    
    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }

    // MARK: - Keychain Cookies
       private func clearKeychainCookies() {
           let kService = "Weblogin SSO Session Cache"
           let query: [String: Any] = [
               kSecClass as String: kSecClassGenericPassword,
               kSecAttrService as String: kService
           ]
           let status = SecItemDelete(query as CFDictionary)
           if status == errSecSuccess {
               print("Keychain cookies deleted")
           } else {
               print("No Keychain cookies found or failed to delete: \(status)")
           }
       }

       // MARK: - WKWebView Session
       private func clearWKWebViewSession() {
           // Clear cookies
           let cookieStore = WKWebsiteDataStore.default().httpCookieStore
           cookieStore.getAllCookies { cookies in
               for cookie in cookies {
                   cookieStore.delete(cookie)
               }
           }
           // Clear caches, localStorage, etc.
           let dataTypes = WKWebsiteDataStore.allWebsiteDataTypes()
           let fromDate = Date(timeIntervalSince1970: 0)
           WKWebsiteDataStore.default().removeData(ofTypes: dataTypes, modifiedSince: fromDate) {
               print("WKWebView session cleared")
           }
       }
}

