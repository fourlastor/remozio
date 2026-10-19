import Foundation

/// Historical transition stages. Each marker requires independent native validation by the authorized setup owner.
enum GatewayRuntimeSettingsPhase: Int64, CaseIterable, Sendable {
    case retained = 0, quiesced = 1, filesPublished = 2, consumersObserved = 3
}
struct GatewayRuntimeSettingsState: Sendable {
    let active: GatewayRuntimeSettingsRevision?
    let pending: GatewayRuntimeSettingsRevision?
    let phase: GatewayRuntimeSettingsPhase?
    static let empty = Self(active: nil, pending: nil, phase: nil)
}
