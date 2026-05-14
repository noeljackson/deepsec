import Foundation
import Security

func storeTokenVulnerable(_ token: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "auth-token",
        kSecValueData as String: token.data(using: .utf8)!,
    ]
    SecItemAdd(query as CFDictionary, nil)
}

func formatTokenPreview(_ token: String) -> String {
    let prefix = token.prefix(6)
    return "token: \(prefix)…"
}
