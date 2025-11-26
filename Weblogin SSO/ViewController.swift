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
//  ViewController.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 22/10/2025.
//

import Cocoa
import WebKit
import Security

class ViewController: NSViewController {

    /*
    @IBAction func logoutButtonPressed(_ sender: Any) {
            clearKeychainCookies()
            clearWKWebViewSession()
            // Any other app-specific logout logic here
            print("User logged out.")
        }
     */
    
    @IBAction func turnOffSwitchToggled (_ sender: NSSwitch) {
        let sharedDefaults = UserDefaults(suiteName: "group.no.uio.weblogin")!
        let isOff = (sender.state == .off)
        sharedDefaults.set(isOff, forKey: "disable_sso")
        sharedDefaults.synchronize()
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

