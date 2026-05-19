//
//  Helpers.swift
//  Weblogin SSO
//
//  Created by Francis Augusto Medeiros-Logeay on 26/11/2025.
//

import Foundation
import CryptoKit
import AuthenticationServices
import LocalAuthentication

extension AuthenticationViewController {


    func deviceSupportsBiometrics() -> Bool {
        let context = LAContext()
        var error: NSError?

        // This returns true only if biometrics are enrolled AND available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
    error: &error) {
            return true
        }

        // If false, check why - hardware might exist but not be enrolled
        if let error = error {
            switch error.code {
            case LAError.biometryNotEnrolled.rawValue:
                // Hardware exists, but user hasn't enrolled biometrics
                return true
            case LAError.biometryNotAvailable.rawValue:
                // No biometric hardware (e.g., desktop Mac without Touch ID)
                return false
            default:
                return false
            }
        }

        return false
    }

    func biometricPolicyFromExtensionData(_ extensionData: [AnyHashable: Any]) -> ASAuthorizationProviderExtensionLoginConfiguration.UserSecureEnclaveKeyBiometricPolicy? {
        // Determine base policy (mutually exclusive - first one wins)
        var policy: ASAuthorizationProviderExtensionLoginConfiguration.UserSecureEnclaveKeyBiometricPolicy?

        if extensionData["UseTouchIDOrWatchCurrentSet"] as? Bool == true {
            policy = .touchIDOrWatchCurrentSet
        } else if extensionData["UseTouchIDOrWatchAny"] as? Bool == true {
            policy = .touchIDOrWatchAny
        }

        // Add modifiers if we have a base policy
        if var policy = policy {
            if extensionData["ReuseUnlock"] as? Bool == true {
                policy.insert(.reuseDuringUnlock)
            }

            if extensionData["PasswordFallback"] as? Bool == true {
                policy.insert(.passwordFallback)
            }

            return policy
        }

        return nil
    }

    func updateConfiguration(loginManager: ASAuthorizationProviderExtensionLoginManager) {
        guard let currentConfig = loginManager.loginConfiguration else {
            logger.warning("webloginlog: No existing configuration to update")
            return
        }

        let extensionData = loginManager.extensionData ?? [:]
        let desiredPolicy = biometricPolicyFromExtensionData(extensionData)

        // Check if device supports biometrics
        let canUseBiometrics = deviceSupportsBiometrics()

        // Determine what the policy should be
        let targetPolicy: ASAuthorizationProviderExtensionLoginConfiguration.UserSecureEnclaveKeyBiometricPolicy?
        if let policy = desiredPolicy, canUseBiometrics {
            targetPolicy = policy
        } else {
            targetPolicy = []
        }

        // Compare with current policy
        let currentPolicy = currentConfig.userSecureEnclaveKeyBiometricPolicy

        if currentPolicy != targetPolicy {
            logger.debug("webloginlog: Biometric policy has changed, updating configuration")

    
            
            if let targetPolicy = targetPolicy, let newConfig = loginManager.loginConfiguration {
                newConfig.userSecureEnclaveKeyBiometricPolicy = targetPolicy
            
                do {
                    try loginManager.saveLoginConfiguration(newConfig)
                    loginManager.deviceRegistrationsNeedsRepair()
                    logger.log("webloginlog: Configuration updated successfully")
                } catch {
                    logger.log("webloginlog: Failed to update configuration: \(error)")
                }
            }

           
        } else {
            logger.debug("webloginlog: Biometric policy unchanged, no update needed")
        }
    }
}

// MARK: - Global Helper Functions (accessible to all)

func htmlEscape(_ s: String) -> String {
    return s
        .replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
}

func base64URLEncode(_ data: Data) -> String {
    let s = data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return s
}

func combineCookies(cookies: [HTTPCookie]) -> String {
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

func computeKid(from publicKey: SecKey) -> String {
    let der = exportPublicKeyDER(publicKey)
    let hash = sha256(der)
    return hash.base64EncodedString()
}

func exportPublicKeyDER(_ key: SecKey) -> Data {
    var error: Unmanaged<CFError>?
    guard let der = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
        fatalError("webloginlog: Could not export public key: \(String(describing: error))")
    }
    return der
}

func sha256(_ data: Data) -> Data {
    let hash = CryptoKit.SHA256.hash(data: data)
    return Data(hash)
}

func decodeJWT(_ jwt: String) -> [String: Any]? {
    let segments = jwt.split(separator: ".")
    guard segments.count >= 2 else { return nil }

    let payloadSegment = segments[1]

    var payload = payloadSegment
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")

    while payload.count % 4 != 0 {
        payload.append("=")
    }

    guard let data = Data(base64Encoded: payload) else { return nil }

    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}
