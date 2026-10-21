import Foundation

/// New local custody choices are never taken from an imported setup file.
public struct SetupPortableImportCustodyChoices: Sendable {
    public let runtimeFiles: Bool
    public let pushCredentials: Bool
    public let relayCredential: Bool
    public init(runtimeFiles: Bool = false, pushCredentials: Bool = false, relayCredential: Bool = false) {
        self.runtimeFiles = runtimeFiles; self.pushCredentials = pushCredentials; self.relayCredential = relayCredential
    }
    func accepts(_ action: SetupPortableImportOperation.Action) -> Bool {
        switch action {
        case .prepareRuntime: runtimeFiles
        case .prepareGateway: pushCredentials
        case .prepareRunCredential: relayCredential
        default: false
        }
    }
}
public enum SetupPortableImportFlowError: Error, Equatable { case custodyNotAccepted, authorizationExpired }
