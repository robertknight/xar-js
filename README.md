# xar-js
[![Build Status](https://travis-ci.org/robertknight/xar-js.png?branch=master)](https://travis-ci.org/robertknight/xar-js)

xar-js is a JavaScript library and command-line utility for reading and writing [xar archives](https://en.wikipedia.org/wiki/Xar_%28archiver%29).

It was originally written to facilitate automated building of Safari Extensions without having to manually build the extension using Extension Builder.

## Installation

`npm install -g xar-js`

## Usage

### Building a Safari Extension

To build a Safari extension without using Extension Builder, you
will first need to get developer certificates for Safari from
Apple, export the certificates and the intermediate and root
certificates in the signing chain. You can then use `xarjs create`
to generate `.safariextz` extensions.

1. You will need a Developer Certificate as described in the [Safari Extension Development Guide](https://developer.apple.com/library/safari/documentation/Tools/Conceptual/SafariExtensionGuide/UsingExtensionBuilder/UsingExtensionBuilder.html)
1. Once you have the Developer Certificate installed in your
   keychain, you will need to export it.
   1. Go to the 'Certificates' section of the 'Keychain Access'
      application, command-click on the 'Safari Developer: ...'
      certificate and select the 'Export' option.
   2. Save the certificate using the .p12 format.
   3. Extract the public and private keys from the resulting
      .p12 file using openssl:

    ````
    # export public certificate
    openssl pkcs12 -in safari-certs.p12 -nokeys -out cert.pem

    # export private key (note the 'nodes' option means that it will be unencrypted)
    openssl pkcs12 -nodes -in safari-certs.p12 -nocerts -out privatekey.pem
    ````
3. Export the intermediate certificate and root certificates used
   to sign your developer certificate from Keychain Access.

   These are the 'Apple Worldwide Developer Relations Certification Authority' (usually in your login keychain) and the 'Apple Root CA' certificate (usually in the 'System Roots' section).
   (These are named `apple-intermdiate.pem` and `apple-root.pem`
    in the following instructions).

   In the export options dialog, select the Privacy Enhanced Mail (PEM) format.
4. Use `xarjs create` to generate a `.safariextz` archive from your
   `.safariextension` directory containing the files for the extension:

   ````
   xarjs create extension.safariextz --cert cert.pem --cert apple-intermediate.pem --cert apple-root.pem --private-key privatekey.pem extension.safariextension
   ````
5. Verify that Safari accepts the resulting extension:
   ````
   open extension.safariextz
   ````
   Should result in Safari showing a dialog prompting you to install
   the extension.
