# Complete Refactoring Guide

## ✅ Files Created

All new files have been created:

1. **Shared.swift** - Global logger and constants
2. **RegistrationHandler.swift** - Registration logic (no WKWebView)
3. **AuthorizationHandler.swift** - Authorization logic (uses WKWebView)
4. **AuthenticationViewController_New.swift** - Simplified coordinator
5. **AuthenticationViewController+WebNavigation.swift** - WKNavigationDelegate methods
6. **Helpers.swift** - Updated with shared helper functions

## 🔧 Steps to Complete in Xcode

### Step 1: Add New Files to Project

1. Open your Xcode project
2. Right-click on the `ssoe` group
3. Select "Add Files to [Project Name]..."
4. Add these files:
   - `Shared.swift`
   - `RegistrationHandler.swift`
   - `AuthorizationHandler.swift`
   - `AuthenticationViewController_New.swift`
   - `AuthenticationViewController+WebNavigation.swift`
5. Make sure "Copy items if needed" is UNCHECKED (files are already in the correct location)
6. Make sure your target is selected

### Step 2: Rename/Remove Old Files

1. **Rename** `AuthenticationViewController.swift` to `AuthenticationViewController_OLD.swift`
2. **Rename** `AuthenticationViewController_New.swift` to `AuthenticationViewController.swift`
3. **Remove** `AuthenticationSession.swift` from the project (functionality moved to RegistrationHandler)
   - Right-click → Delete → "Remove Reference" (don't move to trash yet, keep as backup)

### Step 3: Update Helpers.swift

The file has been updated with:
- `htmlEscape(_:)`
- `base64URLEncode(_:)`  
- `combineCookies(cookies:)`
- Global functions: `computeKid`, `exportPublicKeyDER`, `sha256`, `decodeJWT`

**No action needed** - these are already added.

### Step 4: Build the Project

1. Clean build folder: **Product → Clean Build Folder** (Cmd+Shift+K)
2. Build: **Product → Build** (Cmd+B)

Most SourceKit errors you saw will disappear because all files are now in the same module.

### Step 5: Fix Any Remaining Errors

If you see errors about missing methods in AuthorizationHandler:

**Add to AuthorizationHandler.swift:**
```swift
private func updateConfiguration(loginManager: ASAuthorizationProviderExtensionLoginManager) {
    // Delegate to global helper in Helpers.swift
    guard let viewController = viewController else { return }
    viewController.updateConfiguration(loginManager: loginManager)
}
```

### Step 6: Test All Flows

Test thoroughly:
- ✅ Device registration with registration token
- ✅ Device registration with user login
- ✅ User registration  
- ✅ Authorization with existing SSO tokens
- ✅ Authorization requiring reauthentication
- ✅ SAML flows (POST and REDIRECT)
- ✅ Required actions (MFA, password reset)

## 📋 What Changed

### Before (Monolithic)
```
AuthenticationViewController.swift (1520 lines)
├── Registration logic
├── Authorization logic
├── WKWebView management
├── ASWebAuthenticationSession
└── All helper functions
```

### After (Separated)
```
Shared.swift
├── Global logger
└── Shared constants

RegistrationHandler.swift
├── beginDeviceRegistration
├── beginUserRegistration
├── idpLogin (uses ASWebAuthenticationSession)
├── registerDevice
└── registerUser

AuthorizationHandler.swift
├── beginAuthorization
└── insertPssoTokens (uses WKWebView via viewController)

AuthenticationViewController.swift
├── Coordinator (delegates to handlers)
├── UI management (overlay, spinner)
└── Helper methods (destroyRegistrationWebView, etc.)

AuthenticationViewController+WebNavigation.swift
├── decidePolicyFor (SAML, callback handling)
├── didReceiveServerRedirectForProvisionalNavigation
└── didFinish (password field detection)

Helpers.swift
├── All shared helper functions
└── Biometric policy helpers
```

## 🎯 Benefits

✅ **Clean separation**: Registration vs Authorization  
✅ **No WKWebView in registration**: Uses modern ASWebAuthenticationSession  
✅ **Easier to test**: Each handler is independent  
✅ **Easier to maintain**: Clear responsibilities  
✅ **Reusable helpers**: Shared functions in one place  

## 🐛 Troubleshooting

### "Cannot find type 'AuthenticationViewController'"
**Solution**: Make sure all files are added to the same target in Xcode

### "Cannot find 'logger'"
**Solution**: Make sure `Shared.swift` is added to the project

### "Cannot find 'RegistrationState'"
**Solution**: Make sure `RegistrationState.swift` is in the project and target

### Duplicate symbol errors
**Solution**: Make sure you renamed/removed the old `AuthenticationViewController.swift`

## 📝 Notes

- Keep `AuthenticationViewController_OLD.swift` as backup until fully tested
- Keep `AuthenticationSession.swift` as backup (can delete after testing)
- The SourceKit errors you see in individual files will resolve when built together
- All files share the same module scope, so types are automatically visible

## ✨ Next Steps After Testing

Once everything works:
1. Delete backup files (`_OLD.swift`, `AuthenticationSession.swift`)
2. Commit the refactoring
3. Update documentation if needed
