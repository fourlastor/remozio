import Foundation

public enum GatewaySetupField: String, CaseIterable, Sendable {
    case wakeConnections, wakeOperations, wakeChallenge
    case wakePoll, wakeTimeout, operations, handshake, authorityLease, providerTimeout, schedulerRetry
    case storedControls, pendingPerEnrollment, candidateLifetime, databaseBusy
    case deliveryFlights, sendInterval, retryBase, retryMaximum, probeAttempts, probeDelay, probeTTL
    case wakeEntries, wakeAttempts, enrollmentInterval, wakeLifetime, wakeTTL

    public var initialValue: String {
        switch self {
        case .wakePoll, .schedulerRetry, .databaseBusy, .retryBase, .probeDelay, .enrollmentInterval: "1000"
        case .wakeTimeout, .handshake, .wakeChallenge: "5000"
        case .operations, .wakeOperations: "8"
        case .authorityLease: "15000"
        case .providerTimeout, .probeTTL: "30"
        case .storedControls: "4096"
        case .pendingPerEnrollment, .wakeConnections: "4"
        case .candidateLifetime: "300000"
        case .deliveryFlights, .probeAttempts, .wakeAttempts: "2"
        case .sendInterval: "100"
        case .retryMaximum, .wakeLifetime: "60000"
        case .wakeEntries: "128"
        case .wakeTTL: "60"
        }
    }
}

/// In-memory text fields only. Provider keys never enter preferences or this form value.
public struct GatewaySetupForm: Sendable {
    public var senderID = ""
    public var packageName = "dev.remozio.android"
    public var fileWakeCustodyAccepted = false
    public var fields: [GatewaySetupField: String] = [:]
    public init() {}
    public subscript(_ field: GatewaySetupField) -> String {
        get { fields[field] ?? field.initialValue }
        set { fields[field] = newValue }
    }
    private func number(_ field: GatewaySetupField) throws -> UInt64 {
        let text = self[field]
        guard !text.isEmpty, text.utf8.count <= 20, text.utf8.allSatisfy({ (48...57).contains($0) }),
              let number = UInt64(text) else { throw GatewayPreparationError.invalidRecord }
        return number
    }
    private func int(_ field: GatewaySetupField) throws -> Int {
        guard let value = Int(exactly: try number(field)) else { throw GatewayPreparationError.invalidRecord }; return value
    }
    private func uint32(_ field: GatewaySetupField) throws -> UInt32 {
        guard let value = UInt32(exactly: try number(field)) else { throw GatewayPreparationError.invalidRecord }; return value
    }
    public func activationSettings() throws -> GatewayRuntimeActivationSettings {
        try .init(wakePollMilliseconds: number(.wakePoll), wakeTimeoutMilliseconds: number(.wakeTimeout))
    }
    public func serviceSettings() throws -> GatewayServiceSettings {
        try .init(delivery: GatewayDeliveryPolicy(maximumFlights: int(.deliveryFlights), minimumSendIntervalMillis: number(.sendInterval),
                retryBaseDelayMillis: number(.retryBase), maximumRetryBackoffMillis: number(.retryMaximum)),
            probe: GatewayProbePolicy(maximumAttempts: int(.probeAttempts), minimumRetryDelayMillis: number(.probeDelay), maximumTTLSeconds: uint32(.probeTTL)),
            wake: GatewayWakePolicy(maximumEntries: int(.wakeEntries), maximumAttempts: int(.wakeAttempts),
                minimumEnrollmentIntervalMillis: number(.enrollmentInterval), maximumLifetimeMillis: number(.wakeLifetime), maximumTTLSeconds: uint32(.wakeTTL)),
            maximumOperations: int(.operations), handshakeTimeoutMillis: number(.handshake), authorityLeaseMillis: number(.authorityLease),
            providerTimeoutSeconds: number(.providerTimeout), schedulerRetryMillis: number(.schedulerRetry), maximumStoredControls: int(.storedControls),
            maximumPendingPerEnrollment: int(.pendingPerEnrollment), maximumCandidateLifetimeMillis: number(.candidateLifetime), databaseBusyMillis: uint32(.databaseBusy))
    }
    public func choices(provider: SetupFCMConfiguration) throws -> GatewaySetupPreparationChoices {
        guard fileWakeCustodyAccepted else { throw GatewayPreparationError.custodyNotAccepted }
        _ = try activationSettings()
        return try .init(provider: provider, senderID: senderID, packageName: packageName,
            settings: serviceSettings(), fileWakeCustodyAccepted: true)
    }
    public func settingsSelection() throws -> GatewayRuntimeSettingsSelection {
        try .init(service: serviceSettings(), activation: activationSettings(),
            maximumWakeConnections: int(.wakeConnections), maximumWakeOperations: int(.wakeOperations),
            wakeChallengeLifetimeMilliseconds: number(.wakeChallenge))
    }
    public mutating func selectRetained(_ selection: GatewayRuntimeSettingsSelection) {
        selectRetained(selection.activation)
        self[.wakeConnections] = String(selection.maximumWakeConnections)
        self[.wakeOperations] = String(selection.maximumWakeOperations)
        self[.wakeChallenge] = String(selection.wakeChallengeLifetimeMilliseconds)
        let s = selection.service
        self[.operations] = String(s.maximumOperations); self[.handshake] = String(s.handshakeTimeoutMillis)
        self[.authorityLease] = String(s.authorityLeaseMillis); self[.providerTimeout] = String(s.providerTimeoutSeconds)
        self[.schedulerRetry] = String(s.schedulerRetryMillis); self[.storedControls] = String(s.maximumStoredControls)
        self[.pendingPerEnrollment] = String(s.maximumPendingPerEnrollment); self[.candidateLifetime] = String(s.maximumCandidateLifetimeMillis)
        self[.databaseBusy] = String(s.databaseBusyMillis)
        self[.deliveryFlights] = String(s.delivery.maximumFlights); self[.sendInterval] = String(s.delivery.minimumSendIntervalMillis)
        self[.retryBase] = String(s.delivery.retryBaseDelayMillis); self[.retryMaximum] = String(s.delivery.maximumRetryBackoffMillis)
        self[.probeAttempts] = String(s.probe.maximumAttempts); self[.probeDelay] = String(s.probe.minimumRetryDelayMillis)
        self[.probeTTL] = String(s.probe.maximumTTLSeconds); self[.wakeEntries] = String(s.wake.maximumEntries)
        self[.wakeAttempts] = String(s.wake.maximumAttempts); self[.enrollmentInterval] = String(s.wake.minimumEnrollmentIntervalMillis)
        self[.wakeLifetime] = String(s.wake.maximumLifetimeMillis); self[.wakeTTL] = String(s.wake.maximumTTLSeconds)
    }
    public mutating func selectRetained(_ settings: GatewayRuntimeActivationSettings) {
        self[.wakePoll] = String(settings.wakePollMilliseconds); self[.wakeTimeout] = String(settings.wakeTimeoutMilliseconds)
    }
}

extension SetupFCMConfiguration {
    /// Explicit local import only. This validates credentials without saving them or contacting Firebase.
    public init(serviceAccountJSON data: Data) throws {
        guard !data.isEmpty, data.count <= 65536,
              let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              fields["type"] as? String == "service_account",
              fields["token_uri"] as? String == FCMServiceAccount.tokenEndpoint,
              let project = fields["project_id"] as? String, let email = fields["client_email"] as? String,
              let keyID = fields["private_key_id"] as? String, let pem = fields["private_key"] as? String else {
            throw PortableSetupError.rejected
        }
        try self.init(project: project, clientEmail: email, privateKeyID: keyID, privateKeyPEM: pem)
    }
}

/// Selects initial values once. A refresh does not replace edits; a retained pending transition still owns its exact values.
public struct GatewaySetupFormSelection: Sendable {
    private var selectedRetained = false
    private var selectedFullSettings = false
    private var selectedScope: Data?
    public init() {}
    public mutating func update(form: inout GatewaySetupForm, activation: SetupGatewayActivationProgress?,
                                settings: SetupGatewaySettingsProgress?, initial: GatewayRuntimeSettingsSelection?) {
        let scope = (settings?.activation ?? activation).map { $0.setup.accountID + $0.setup.foregroundDigest }
        if selectedScope != scope {
            selectedRetained = false; selectedFullSettings = false; selectedScope = scope
        }
        if let settings, !selectedFullSettings || settings.stage != nil,
           let selection = try? settings.pendingSelection ?? settings.currentSelection {
            form.selectRetained(selection); selectedRetained = true; selectedFullSettings = true; return
        }
        if !selectedRetained, let saved = activation?.settings {
            form.selectRetained(saved); selectedRetained = true; return
        }
        if !selectedRetained, let initial {
            if form.fields.isEmpty { form.selectRetained(initial) }
            selectedRetained = true
        }
    }
}
