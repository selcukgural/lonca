// lonca-se: human signatures with user presence, backed by the Secure Enclave.
//
//   lonca-se available                 exit 0 if this Mac has a Secure Enclave
//   lonca-se keygen <keyfile>          create a P-256 key; prints the public key
//                                      (SEC1 uncompressed, hex)
//   lonca-se public <keyfile>          print the public key of an existing key
//   lonca-se sign <keyfile>            sign stdin, which must be a Lonca intent
//                                      (what `lonca` signs for an operation or a
//                                      login); Touch ID or the login password is
//                                      required for every signature, and the
//                                      dialog says what the intent is, read from
//                                      stdin itself; prints a DER ECDSA signature
//                                      (hex) over SHA-256(stdin)
//   lonca-se describe                  print what `sign` would show for stdin
//
// The key file holds the Secure Enclave's wrapped key blob: it is useless on
// any other device and can not sign without the user being present.
//
// The dialog's text is never the caller's. A program that runs as the human
// can call this helper as `lonca` does; what it can not do is have one thing
// signed under the name of another. `sign` takes no text (one given by an
// older `lonca` is ignored) and refuses bytes that are not an intent.
// The texts are those of `describe` in crates/lonca-cli/src/ctx.rs; a test
// there holds the two together.

import CryptoKit
import Foundation
import LocalAuthentication

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func fail(_ message: String) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(1)
}

/// The most an intent is read: an operation of the log holds less.
let maxIntent = 1 << 20

/// Text from the intent as a dialog shows it: no control or format
/// characters (a line break or a bidi mark would redraw the dialog).
func shown(_ s: String) -> String {
    String(String.UnicodeScalarView(s.unicodeScalars.filter {
        switch $0.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse,
             .unassigned:
            return false
        default:
            return true
        }
    }))
}

func string(_ v: Any?) -> String? { (v as? String).map(shown) }

func integer(_ v: Any?) -> Int64? {
    guard let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
    // As it is written, or not at all: 1.5 is no count of milliseconds.
    return Int64(n.stringValue)
}

/// A whole number that is not negative, as it is written: an entry's
/// number is 64 bits without a sign.
func number(_ v: Any?) -> String? {
    guard let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
    let written = n.stringValue
    let digits = !written.isEmpty && written.unicodeScalars.allSatisfy { ("0"..."9").contains($0) }
    return digits ? written : nil
}

func prefix(_ v: Any?, _ n: Int) -> String? { string(v).map { String($0.prefix(n)) } }

func duration(_ ms: Int64) -> String {
    if ms > 0 && ms % 3_600_000 == 0 { return "\(ms / 3_600_000)h" }
    if ms > 0 && ms % 60_000 == 0 { return "\(ms / 60_000)m" }
    if ms > 0 && ms % 1000 == 0 { return "\(ms / 1000)s" }
    return "\(ms)ms"
}

/// What an operation is, for the person asked to touch. nil: not one.
func operation(_ op: [String: Any]) -> String? {
    guard let kind = string(op["op"]) else { return nil }
    switch kind {
    case "repo.init":
        return "create the repository"
    case "human.enroll":
        guard let human = string(op["human"]) else { return nil }
        return "enroll \(human) as a human"
    case "human.rotate":
        guard let human = string(op["human"]) else { return nil }
        return "REPLACE the key of \(human)"
    case "human.revoke":
        guard let human = string(op["human"]) else { return nil }
        return "REVOKE \(human) and end their sessions"
    case "human.recovery_key":
        guard let human = string(op["human"]) else { return nil }
        return "set a recovery key for \(human)"
    case "human.recover":
        guard let human = string(op["human"]) else { return nil }
        return "RECOVER \(human) with the recovery key"
    case "daemon.rotate":
        guard let key = prefix(op["key"], 16) else { return nil }
        return "REPLACE the daemon key with \(key)"
    case "daemon.recover":
        guard let key = prefix(op["key"], 16) else { return nil }
        var also = ""
        if let recover = op["recover"] as? [String: Any] {
            guard let human = string(recover["human"]) else { return nil }
            also = " and RECOVER \(human) with the recovery key"
        }
        return "HAND the repository to daemon key \(key)\(also) (approve only for your own daemon)"
    case "policy.update":
        return "change the repository policy"
    case "session.start":
        guard let agent = string(op["agent"]),
              let scope = op["scope"] as? [String: Any],
              let list = scope["paths"] as? [Any]
        else { return nil }
        let paths = list.compactMap { string($0) }
        guard paths.count == list.count else { return nil }
        let on = paths.joined(separator: ", ")
        var what = "start agent \(agent) on \(on)"
        if let continues = op["continues"] as? [String: Any] {
            guard let session = string(continues["session"]),
                  let widen = continues["widen"] as? Bool
            else { return nil }
            what = widen
                ? "WIDEN session \(session) as agent \(agent) on \(on)"
                : "continue session \(session) as agent \(agent) on \(on)"
        }
        if let harness = string(op["harness"]) { what += ", under \(harness)" }
        return what
    case "session.end":
        guard let session = string(op["session"]) else { return nil }
        return "end session \(session)"
    case "cap.revoke":
        guard let session = string(op["session"]) else { return nil }
        return "revoke session \(session)"
    case "lease.release":
        guard let set = string(op["set"]) else { return nil }
        return "release lease set \(set)"
    case "change.propose":
        guard let change = prefix(op["change"], 12) else { return nil }
        return "propose change \(change)"
    case "change.withdraw":
        guard let change = prefix(op["change"], 12) else { return nil }
        return "withdraw change \(change)"
    case "approve":
        guard let target = number(op["target_seq"]) else { return nil }
        let list = op["checks"] as? [Any] ?? []
        let checks = list.compactMap { string($0) }
        guard checks.count == list.count else { return nil }
        if checks.isEmpty { return "APPROVE operation #\(target)" }
        return "APPROVE operation #\(target), owing checks \(checks.joined(separator: ", "))"
    case "reject":
        guard let target = number(op["target_seq"]) else { return nil }
        return "REJECT operation #\(target)"
    case "import.external":
        guard let remote = string(op["remote"]) else { return nil }
        return "import from \(remote)"
    case "bridge.push":
        guard let remote = string(op["remote"]) else { return nil }
        return "push to \(remote)"
    case "freeze":
        return "freeze the repository"
    case "unfreeze":
        return "unfreeze the repository"
    case "redact":
        guard let blob = prefix(op["blob"], 10) else { return nil }
        return "redact \(blob)"
    default:
        return kind
    }
}

struct NotAnIntent: Error {
    let why: String
    init(_ why: String) { self.why = "not an intent: " + why }
}

/// The dialog's text for the bytes to be signed, or why they are not signed.
func describe(_ data: Data) -> Result<String, NotAnIntent> {
    guard data.count <= maxIntent else { return .failure(NotAnIntent("too long")) }
    guard let json = try? JSONSerialization.jsonObject(with: data),
          let intent = json as? [String: Any],
          let purpose = intent["purpose"] as? String
    else { return .failure(NotAnIntent("no JSON object with a purpose")) }
    switch purpose {
    case "lonca-human-intent-v1", "lonca-human-intent-v2":
        guard let repo = string(intent["repo"]),
              let op = intent["op"] as? [String: Any],
              let what = operation(op)
        else { return .failure(NotAnIntent("no repository and operation")) }
        return .success("Lonca (\(repo)): \(what)")
    case "lonca-human-login-v1":
        guard let human = string(intent["human"]), let ttl = integer(intent["ttl_ms"]) else {
            return .failure(NotAnIntent("no human and time"))
        }
        let to = string(intent["repo"]).map { " to \($0)" } ?? ""
        return .success(
            "Lonca: sign in as \(human)\(to) for \(duration(ttl)) (reads and prepares only)")
    default:
        return .failure(NotAnIntent("purpose \(shown(purpose))"))
    }
}

func input() -> Data {
    // One byte past the limit, so that too long is seen and not read.
    (try? FileHandle.standardInput.read(upToCount: maxIntent + 1)) ?? Data()
}

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: lonca-se available|keygen|public|sign|describe ...") }

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

case "describe":
    guard args.count == 2 else { fail("usage: lonca-se describe") }
    switch describe(input()) {
    case .success(let text): print(text)
    case .failure(let e): fail("describe: \(e.why)")
    }

case "sign":
    // A fourth argument was the dialog's text once; it is not read.
    guard args.count == 3 || args.count == 4 else { fail("usage: lonca-se sign <keyfile>") }
    let message = input()
    let reason: String
    switch describe(message) {
    case .success(let text): reason = text
    case .failure(let e): fail("sign: \(e.why)")
    }
    do {
        let blob = try Data(contentsOf: URL(fileURLWithPath: args[2]))
        let context = LAContext()
        context.localizedReason = reason
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let signature = try key.signature(for: message)
        print(hex(signature.derRepresentation))
    } catch {
        fail("sign: \(error)")
    }

default:
    fail("unknown command \(args[1])")
}
