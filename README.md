# Weblogin SSO Extension

This is a macOS Platform SSO Extension developed at the University of Oslo for use with [Apple Platform Single Sign-on for macOS](https://support.apple.com/en-ca/guide/deployment/dep7bbb05313/web) and a Keycloak IdP that has installed the [Keycloak Platform Single Sign-on extension](https://github.com/unioslo/keycloak-psso-extension).

## Features

- Allows users with registered devices to login in passwordless (when using the Secure Enclave Authentication Method) to Keycloak



## Known limitations

- Due to design choices, when the IdP requires reauthentication and the AuthenticationMethod is "Password", the reauthentication process is handled entirely by Keycloak. When using Secure Enclave, a local re-authentication is used.

## How to use it

Compile this with XCode and install on your Mac. It requires a companion MDM profile. 

More information about how to configure this extension to your own use can be found on the wiki page of this repo: https://github.com/unioslo/weblogin-mac-sso-extension/wiki


## Acknowledgement

Thanks to Timothy Perfitt from [Twocanoes](https://twocanoes.com) for the inspiration provided with their tutorials and code regarding SSO Extensions. His tutorial code on how to build a [SSO Extension](https://twocanoes.com/building-a-single-sign-on-extension-on-macos/) was particularly useful to understand a few concepts regarding how SSO Extensions work.
