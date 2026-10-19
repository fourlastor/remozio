import Foundation

/// Trusted runtime access after native invocation authentication. It never owns or replaces the foreground service.
struct AuthorityGatewaySettingsAccess: Sendable {
    private weak var service: AuthorityWakeService?
    let binding: GatewaySettingsControlBinding
    let verifyCurrent: @Sendable () throws -> Void
    init(service: AuthorityWakeService, binding: GatewaySettingsControlBinding,
         verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        guard service.gatewaySettingsBinding == binding else { throw GatewayPreparationError.changedScope }
        self.service = service; self.binding = binding; self.verifyCurrent = verifyCurrent
    }
    func execute(_ request: GatewaySettingsControlRequest) async throws -> GatewaySettingsControlObservation {
        guard request.binding == binding, let service else { throw GatewayPreparationError.changedScope }
        try verifyCurrent(); try Task.checkCancellation()
        switch request.action {
        case .observe: break
        case .quiesce: try await service.quiescePhonePushSettings(request.change, verifyCurrent: verifyCurrent)
        case .accept: _ = try await service.acceptPhonePushSettings(request.change, verifyCurrent: verifyCurrent)
        }
        let result = try await service.gatewaySettingsObservation(request.change)
        try verifyCurrent(); try Task.checkCancellation()
        if request.action == .quiesce, result != .suspended { throw GatewayPreparationError.changedScope }
        if request.action == .accept, result != .accepted && result != .providerInstalled { throw GatewayPreparationError.changedScope }
        return result
    }
}
