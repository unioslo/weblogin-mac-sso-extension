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

import AuthenticationServices

/// The part of ASAuthorizationProviderExtensionLoginManager the authorization
/// path (beginAuthorization, step-up, token signing) uses. Registration keeps
/// the concrete class. Test builds substitute TestStubLoginManager.
protocol LoginManaging: AnyObject {
    var isDeviceRegistered: Bool { get }
    var isUserRegistered: Bool { get }
    var ssoTokens: [AnyHashable: Any]? { get }
    var extensionData: [AnyHashable: Any] { get }
    var authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod { get }
    var loginUserName: String? { get }
    var jwksEndpointURL: URL? { get }
    func key(for keyType: ASAuthorizationProviderExtensionKeyType) -> SecKey?
    func userNeedsReauthentication(completion: @escaping @Sendable (Error?) -> Void)
}

extension ASAuthorizationProviderExtensionLoginManager: LoginManaging {
    var loginUserName: String? { userLoginConfiguration?.loginUserName }
    var jwksEndpointURL: URL? { loginConfiguration?.jwksEndpointURL }
}

/// The login manager the authorization path uses for this request.
func authorizationLoginManager(for request: ASAuthorizationProviderExtensionAuthorizationRequest) -> (any LoginManaging)? {
#if TESTSTUBS
    if let real = request.loginManager, let stub = TestStubLoginManager.load(wrapping: real) {
        return stub
    }
#endif
    return request.loginManager
}
