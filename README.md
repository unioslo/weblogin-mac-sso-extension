# Weblogin SSO Extension

This is a macOS Platform SSO Extension developed at the University of Oslo for use with [Apple Platform Single Sign-on for macOS](https://support.apple.com/en-ca/guide/deployment/dep7bbb05313/web) and a Keycloak IdP that has installed the [Keycloak Platform Single Sign-on extension](https://github.com/unioslo/keycloak-psso-extension).

## Features

- Allows users with registered devices to login in passwordless to Keycloak



## Known limitations

- **Secure Enclave-only**: this extension only implements the Secure Enclave authentication method. 
- **works poorly with required actions**: When re-authentication is needed because of a required action, the extension doesn't behave well.
- **SAML clients has some quirks**: We have tested very few SAML flows, so some test is further required. 

## How to use it

Compile this with XCode and install on your Mac. It requires a companion MDM profile, such as this one: 

```
<plist version="1.0">
  <dict>
    <key>PayloadContent</key>
    <array>
      <dict>
        <key>BaseURL</key>
        <string>https://uio.keycloak.no/realms/uio/</string>
        <key>Issuer</key>
        <string>https://uio.keycloak.no/</string>
        <key>Audience</key>
        <string>psso</string>
        <key>ClientID</key>
        <string>psso</string>
        <key>PayloadDisplayName</key>
        <string>Weblogin SSOE</string>
        <key>PayloadIdentifier</key>
        <string>mdscentral.00A38C42-503B-4016-A86D-2186CDA5989C.no.uio.WebloginSSO.3E7FAF27-6179-46AA-B1A3-B55E08D3273D</string>
        <key>PayloadOrganization</key>
        <string></string>
        <key>PayloadType</key>
        <string>no.uio.WebloginSSO.ssoe</string>
        <key>PayloadUUID</key>
        <string>3F7FDF27-6179-46AA-B1A3-B55E08D3273D</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
      </dict>
      <dict>
        <key>PayloadDisplayName</key>
        <string>Weblogin Platform SSO</string>
        <key>PayloadIdentifier</key>
        <string>mdscentral.00A38C42-503B-4016-A86D-2186CDA5989C</string>
        <key>PayloadOrganization</key>
        <string></string>
        <key>PayloadScope</key>
        <string>System</string>
        <key>PayloadType</key>
        <string>Configuration</string>
        <key>PayloadUUID</key>
        <string>851A1B46-6A8A-442B-91CB-BC12FF416766</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
      </dict>
      <dict>
        <key>AuthenticationMethod</key>
        <string>UserSecureEnclaveKey</string>
        <key>ExtensionIdentifier</key>
        <string>no.uio.WebloginSSO.ssoe</string>
        <key>PayloadDisplayName</key>
        <string>Weblogin SSO</string>
        <key>PayloadIdentifier</key>
        <string>com.apple.extensiblesso.CA351D35-96B1-41CF-B25B-DF3273189AAD</string>
        <key>PayloadOrganization</key>
        <string></string>
        <key>PayloadType</key>
        <string>com.apple.extensiblesso</string>
        <key>PayloadUUID</key>
        <string>4B7148CD-1069-4140-95CE-78F61BCD9C2B</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>URLs</key>
        <array>
          <string>https://uio.keycloak.no/realms/uio/protocol/</string>
          <string>https://uio.keycloak.no/realms/uio/psso</string>
        </array>
        <key>PlatformSSO</key>
        <dict>
          <key>AccountDisplayName</key>
          <string>Universitet i Oslo - Weblogin</string>
          <key>AuthenticationMethod</key>
          <string>UserSecureEnclaveKey</string>
          <key>EnableAuthorization</key>
          <true />
          <key>EnableCreateUserAtLogin</key>
          <true />
          <key>NewUserAuthorizationMode</key>
          <string>Groups</string>
          <key>UseSharedDeviceKeys</key>
          <true />
          <key>UserAuthorizationMode</key>
          <string>Groups</string>
          <key>AllowDeviceIdentifiersInAttestation</key>
          <true />
        </dict>
        <key>TeamIdentifier</key>
        <string>YOURTEAM</string>
        <key>Type</key>
        <string>Redirect</string>
      </dict>
    </array>
    <key>PayloadDescription</key>
    <string></string>
    <key>PayloadDisplayName</key>
    <string>Weblogin Platform SSO test/V_41</string>
    <key>PayloadIdentifier</key>
    <string>37f5c3b4-36c6-101f-9485-90082e154a1a</string>
    <key>PayloadOrganization</key>
    <string></string>
    <key>PayloadRemovalDisallowed</key>
    <false />
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>dbacb344-7490-4948-b51a-b395d948fd54_41</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadScope</key>
    <string>System</string>
  </dict>
</plist>
```

We will update this page in the future, but the steps to use this extension are the same as those described here: 
https://twocanoes.com/building-a-single-sign-on-extension-on-macos/



## Acknowledgement

Thanks to Timothy Perfitt from [Twocanoes](https://twocanoes.com) for the inspiration provided with their tutorials and code regarding SSO Extensions. His tutorial code on how to build a [SSO Extension](https://twocanoes.com/building-a-single-sign-on-extension-on-macos/) was particularly useful to understand a few concepts regarding how SSO Extensions work.