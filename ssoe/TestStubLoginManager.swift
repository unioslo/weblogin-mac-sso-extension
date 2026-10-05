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

#if TESTSTUBS

import AuthenticationServices
import Foundation

/// Stands in for the OS login manager so the authorization path runs on a VM
/// without Secure Enclave registration. Active only in a build compiled with
/// TESTSTUBS whose app group container holds psso-test-stub.json. Registration
/// state, tokens, the signing key and the reauthentication outcome come from
/// that file. extensionData still comes from the real manager (the MDM profile).
final class TestStubLoginManager: LoginManaging {

    static let configFileName = "psso-test-stub.json"
    // Longer than 15 bytes on purpose: Swift stores shorter literals inline, and
    // build-test-pkg.sh greps the binary for this marker with strings(1).
    static let activeMarker = "TESTSTUB login manager active"

    enum Reauthentication: String, Decodable { case succeed, fail, hang }

    enum TokenValue: Decodable {
        case string(String)
        case int(Int)

        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let i = try? c.decode(Int.self) { self = .int(i); return }
            self = .string(try c.decode(String.self))
        }

        var any: Any {
            switch self {
            case .string(let s): return s
            case .int(let i): return i
            }
        }
    }

    struct Config: Decodable {
        var username: String
        var authenticationMethod: String
        var ssoTokens: [String: TokenValue]
        var signingKeyX963Base64: String
        var reauthentication: Reauthentication
    }

    private let config: Config
    private let signingKey: SecKey
    private let real: (any LoginManaging)?

    init?(json: Data, wrapping real: (any LoginManaging)?) {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        guard let config = try? decoder.decode(Config.self, from: json) else {
            logger.error("webloginlog: TESTSTUB config does not decode")
            return nil
        }
        guard let key = TestStubLoginManager.importPrivateKey(x963Base64: config.signingKeyX963Base64) else {
            logger.error("webloginlog: TESTSTUB signing key does not import")
            return nil
        }
        self.config = config
        self.signingKey = key
        self.real = real
    }

    /// Reads the config file from the app group container, or returns nil when absent.
    static func load(wrapping real: any LoginManaging) -> TestStubLoginManager? {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.no.uio.weblogin") else {
            return nil
        }
        let url = container.appendingPathComponent(configFileName)
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard let stub = TestStubLoginManager(json: data, wrapping: real) else { return nil }
        logger.log("webloginlog: \(activeMarker, privacy: .public) for user \(stub.config.username) (\(stub.config.reauthentication.rawValue, privacy: .public))")
        return stub
    }

    /// X9.63 private key bytes (04 || X || Y || K) as Security expects for P-256.
    static func importPrivateKey(x963Base64: String) -> SecKey? {
        guard let data = Data(base64Encoded: x963Base64), data.count == 97 else { return nil }
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 256,
        ]
        return SecKeyCreateWithData(data as CFData, attrs as CFDictionary, nil)
    }

    // MARK: LoginManaging

    var isDeviceRegistered: Bool { true }
    var isUserRegistered: Bool { true }

    var ssoTokens: [AnyHashable: Any]? {
        var out: [AnyHashable: Any] = [:]
        for (k, v) in config.ssoTokens { out[k] = v.any }
        return out
    }

    var extensionData: [AnyHashable: Any] { real?.extensionData ?? [:] }

    var authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod {
        config.authenticationMethod == "secure_enclave" ? .userSecureEnclaveKey : .password
    }

    var loginUserName: String? { config.username }
    // Never the real loginConfiguration: reading it on an unregistered device hangs.
    // nil makes verifyStepUpJWT use the BaseURL JWKS, which a registration would save.
    var jwksEndpointURL: URL? { nil }

    func key(for keyType: ASAuthorizationProviderExtensionKeyType) -> SecKey? {
        keyType == .sharedDeviceSigning ? signingKey : nil
    }

    func userNeedsReauthentication(completion: @escaping @Sendable (Error?) -> Void) {
        switch config.reauthentication {
        case .succeed:
            DispatchQueue.main.async { completion(nil) }
        case .fail:
            DispatchQueue.main.async {
                completion(NSError(domain: "psso.teststub", code: 1,
                                   userInfo: [NSLocalizedDescriptionKey: "TESTSTUB reauthentication failed"]))
            }
        case .hang:
            break
        }
    }
}

#endif
