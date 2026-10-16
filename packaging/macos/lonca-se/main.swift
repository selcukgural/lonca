// lonca-se: human signatures with user presence, backed by the Secure Enclave.
//
//   lonca-se available                 exit 0 if this Mac has a Secure Enclave
//   lonca-se keygen <keyfile>          create a P-256 key; prints the public key
//                                      (SEC1 uncompressed, hex)
//   lonca-se public <keyfile>          print the public key of an existing key
//   lonca-se sign <keyfile> <reason>   sign stdin; Touch ID or the login password
//                                      is required for every signature; prints a
//                                      DER ECDSA signature (hex) over SHA-256(stdin)
//
// The key file holds the Secure Enclave's wrapped key blob: it is useless on
// any other device and can not sign without the user being present.

import CryptoKit
import Foundation
import LocalAuthentication

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(1)
}

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: lonca-se available|keygen|public|sign ...") }

switch args[1] {
case "available":
    exit(SecureEnclave.isAvailable ? 0 : 1)

case "keygen":
    guard args.count == 3 else { fail("usage: lonca-se keygen <keyfile>") }
    guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave") }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error
    ) else {
        fail("access control: \(error!.takeRetainedValue())")
    }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let url = URL(fileURLWithPath: args[2])
        try key.dataRepresentation.write(to: url, options: [.withoutOverwriting])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        print(hex(key.publicKey.x963Representation))
    } catch {
        fail("keygen: \(error)")
    }

case "public":
    guard args.count == 3 else { fail("usage: lonca-se public <keyfile>") }
    do {
        let blob = try Data(contentsOf: URL(fileURLWithPath: args[2]))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        print(hex(key.publicKey.x963Representation))
    } catch {
        fail("public: \(error)")
    }

case "sign":
    guard args.count == 4 else { fail("usage: lonca-se sign <keyfile> <reason>") }
    do {
        let blob = try Data(contentsOf: URL(fileURLWithPath: args[2]))
        let context = LAContext()
        context.localizedReason = args[3]
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let message = FileHandle.standardInput.readDataToEndOfFile()
        let signature = try key.signature(for: message)
        print(hex(signature.derRepresentation))
    } catch {
        fail("sign: \(error)")
    }

default:
    fail("unknown command \(args[1])")
}
