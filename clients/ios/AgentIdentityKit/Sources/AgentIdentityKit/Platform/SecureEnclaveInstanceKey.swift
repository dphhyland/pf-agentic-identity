import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The instance key in the Secure Enclave, through the Security framework: a P-256 key made by
/// `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, kept as a permanent keychain item under an
/// application tag the app names, and never outside the enclave. Cannot run under test: a simulator and a CI
/// runner have no Secure Enclave.
///
/// `SecKeyCreateSignature` with `.ecdsaSignatureMessageX962SHA256` hashes the JWS Signing Input with SHA-256, as
/// ES256 does, and returns DER; `sign` hands back R || S (`ES256.rawSignature(fromDER:)`). Behind a gate, signing
/// prompts and blocks until the owner answers, so it must not be called on the main actor.
public final class SecureEnclaveInstanceKey: InstanceKey, @unchecked Sendable {

    /// What the enclave requires before it signs. The server-side time-box does not depend on this: a
    /// biometry gate proves the owner was present at some point, and only a PingOne sign-in moves
    /// `uv_last_verified_at`.
    public enum Gate: Sendable {
        case none
        case userPresence
        case biometryCurrentSet

        var flags: SecAccessControlCreateFlags {
            switch self {
            case .none: return [.privateKeyUsage]
            case .userPresence: return [.privateKeyUsage, .userPresence]
            case .biometryCurrentSet: return [.privateKeyUsage, .biometryCurrentSet]
            }
        }
    }

    /// False on a simulator, on a CI runner and on a Mac without the enclave.
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    private let key: SecKey
    public let publicJWK: PublicJWK

    private init(key: SecKey) throws {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw AgentIdentityError.secureEnclave("the instance key has no public half")
        }
        var error: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw AgentIdentityError.secureEnclave(Self.describe(error))
        }
        // An EC public key's external representation is the X9.62 uncompressed point, 0x04 || X || Y.
        self.key = key
        self.publicJWK = try PublicJWK(p256X963: point)
    }

    /// A new key under `tag`, replacing any the tag held. Creating one never prompts, even behind a gate.
    public static func create(tag: String, gate: Gate) throws -> SecureEnclaveInstanceKey {
        try delete(tag: tag)
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           gate.flags, &error) else {
            throw AgentIdentityError.secureEnclave(describe(error))
        }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        attributes.merge(keychain) { $1 }
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw AgentIdentityError.secureEnclave(describe(error))
        }
        return try SecureEnclaveInstanceKey(key: key)
    }

    /// The key under `tag`, or nil. `context` is an `LAContext` the app has already evaluated, so that signing
    /// inside its window does not prompt again.
    public static func load(tag: String, context: LAContext? = nil) throws -> SecureEnclaveInstanceKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecReturnRef as String: true,
        ]
        query.merge(keychain) { $1 }
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw AgentIdentityError.secureEnclave("the keychain did not return the instance key: OSStatus \(status)")
        }
        return try SecureEnclaveInstanceKey(key: item as! SecKey)
    }

    /// Removes the key under `tag`. After `DeviceAgent.forget()`: a new enrolment takes a new key.
    public static func delete(tag: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
        ]
        query.merge(keychain) { $1 }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AgentIdentityError.secureEnclave("the keychain refused to delete the instance key: OSStatus \(status)")
        }
    }

    public func sign(_ signingInput: Data) async throws -> Data {
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, signingInput as CFData,
                                              &error) as Data? else {
            throw AgentIdentityError.secureEnclave(Self.describe(error))
        }
        return try ES256.rawSignature(fromDER: der)
    }

    /// On a Mac, a Secure Enclave key lives in the data protection keychain, as it always does on iOS. The Mac is
    /// where the package's tests run; a Mac app holding its instance key here has not been tried.
    private static var keychain: [String: Any] {
        #if os(macOS)
        return [kSecUseDataProtectionKeychain as String: true]
        #else
        return [:]
        #endif
    }

    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "the Security framework gave no reason" }
        return (error as Error).localizedDescription
    }
}
