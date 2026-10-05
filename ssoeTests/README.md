# ssoeTests

Unit tests for the `ssoe` app extension.

A test bundle cannot import an app extension's module, so this target compiles
the `ssoe/*.swift` sources directly and the tests call internal methods without
`@testable import`.

The `ssoe` target picks up new files under `ssoe/` automatically. This target
does not. When you add a Swift file under `ssoe/`, also add it to the ssoeTests
target (Xcode: File Inspector, Target Membership), or the test build fails with
unresolved symbols.

Keep tests pure: no network, keychain, Secure Enclave or biometrics.

Run: `xcodebuild test -scheme ssoeTests -destination 'platform=macOS'`

This target compiles with `TESTSTUBS`, so `ssoe/TestStubLoginManager.swift`
exists in tests. The app and extension targets do not define it; only
`testing/build-test-pkg.sh` does, for the VM harness.
