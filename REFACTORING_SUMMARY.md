# Refactoring Summary

## Files Created

1. **RegistrationHandler.swift** - Handles all registration flows (device + user)
   - Uses ASWebAuthenticationSession for authentication
   - No dependency on WKWebView
   - Contains: `beginDeviceRegistration`, `beginUserRegistration`, `idpLogin`, `registerDevice`, `registerUser`

2. **AuthorizationHandler.swift** - Handles authorization flows
   - Uses WKWebView for authentication (accessed via weak viewController reference)
   - Contains: `beginAuthorization`, `insertPssoTokens`

3. **AuthenticationViewController_New.swift** - Simplified coordinator view controller
   - Owns the handlers
   - Implements protocol requirements by delegating to handlers
   - Keeps WKNavigationDelegate methods (they need webView access)
   - Keeps UI-related code (overlay, spinner, etc.)

## What Needs To Be Done

### Step 1: Fix Compilation Errors

Common issues to fix:
- Missing `RegistrationState` - needs to be accessible (it's in a separate file)
- Missing `logger` - needs to be accessible globally
- Missing helper functions like `computeKid`, `decodeJWT`, `htmlEscape`, etc.

### Step 2: Move Shared Helpers

Move these to `Helpers.swift` so both handlers can use them:
- `computeKid(from:)`
- `exportPublicKeyDER(_:)`
- `sha256(_:)`
- `decodeJWT(_:)`
- `htmlEscape(_:)`
- `base64URLEncode(_:)`
- `updateConfiguration(loginManager:)` - already in Helpers
- `deviceSupportsBiometrics()` - already in Helpers
- `biometricPolicyFromExtensionData(_:)` - already in Helpers

### Step 3: Add WKNavigationDelegate to New View Controller

The WKNavigationDelegate methods (`decidePolicyFor`, `didReceiveServerRedirectForProvisionalNavigation`, `didFinish`) need to stay in AuthenticationViewController but access authorization handler state:

```swift
extension AuthenticationViewController {
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // Delegate to authorizationHandler or keep inline with access to authorizationHandler properties
    }
}
```

### Step 4: Update Xcode Project

Add new files to the Xcode project:
- RegistrationHandler.swift
- AuthorizationHandler.swift

Remove or rename:
- AuthenticationViewController.swift → AuthenticationViewController_Old.swift (backup)
- AuthenticationViewController_New.swift → AuthenticationViewController.swift
- AuthenticationSession.swift (functionality moved to RegistrationHandler)

### Step 5: Test

Test both flows:
1. Device registration
2. User registration  
3. Authorization with SSO tokens
4. Authorization requiring reauthentication
5. SAML flows

## Benefits of This Refactoring

✅ **Separation of concerns**: Registration vs Authorization logic separated
✅ **No webView in registration**: Registration uses ASWebAuthenticationSession
✅ **Easier to test**: Each handler can be tested independently
✅ **Easier to maintain**: Clear boundaries between responsibilities
✅ **Shared utilities**: Common helpers in one place

## Current Status

- [x] RegistrationHandler.swift created
- [x] AuthorizationHandler.swift created
- [x] AuthenticationViewController_New.swift created
- [ ] Fix compilation errors
- [ ] Move shared helpers to Helpers.swift
- [ ] Add WKNavigationDelegate methods to new view controller
- [ ] Update Xcode project
- [ ] Test all flows
