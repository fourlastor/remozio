enum MacServiceNamespace {
    static func accepts(_ value: String) -> Bool {
        value == "dev.sebastiano.remozio.macos" || value.hasPrefix("dev.sebastiano.remozio.macos.") ||
            value.hasPrefix("dev.remozio.")
    }
}
