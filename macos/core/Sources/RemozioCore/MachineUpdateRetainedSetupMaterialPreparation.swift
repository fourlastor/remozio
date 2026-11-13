import Darwin
import Foundation

/// Retains runtime material before the startup policy write. Consumer files, activation and registration remain separate operations.
enum MachineUpdateRetainedSetupMaterialPreparation {
    typealias Snapshot = MachineUpdateRetainedSetupMaterialSnapshot
    typealias Scope = MachineUpdateStableRuntimePublication.Scope

    static func prepareNative(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        currentCodePolicy: AuthorityCodePolicy, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        fileCustodyAccepted: Bool, verifyCurrent: @escaping (Snapshot) throws -> Void) throws -> RuntimePreparationState {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        try expected.requireCurrent(machine: machine, candidate: candidate)
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let inventory = expected.runtime.setup.source.actual.inventory
        guard inventory.bundlePath == MachineBootstrap.bundlePath,
              let app = currentCodePolicy.entries.first(where: { $0.role == .app && $0.active }),
              let setup = currentCodePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        let bundle = URL(fileURLWithPath: inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        let identity = try placement.preparationCopyIdentity(name: bundle.lastPathComponent)
        func verifyNative(_ actual: Snapshot) throws {
            try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
            let source = actual.runtime.setup.source.actual
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try source.inventory.compareRelease(release)
            guard try InstallationInventory.digest(release) == InstallationInventory.digest(candidate) else { throw RuntimePreparationError.changedScope }
            try source.seal.requireCurrentInventory(source.inventory, epoch: source.installed, candidate: release)
            try RuntimeRetainedSetupReleaseBinding.requireFormats(release)
            try ReleaseGenerationPreflight.validate(release, against: currentCodePolicy)
            for entry in [app, setup] {
                guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                      component.teamID == entry.teamID, component.identifier == entry.identifier,
                      component.generation == entry.installedGeneration,
                      release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash else { throw RuntimePreparationError.changedScope }
            }
            let local = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
                approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
            guard try DynamicCodeValidation.selfPath() == inventory.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw RuntimePreparationError.changedScope
            }
            try actual.runtime.setup.requireOwner(LocalAccountDirectory.lookup(uid: actual.runtime.setup.owner.uid))
            try verifyCurrent(actual); try placement.validate()
            guard try placement.preparationCopyIdentity(name: bundle.lastPathComponent) == identity else { throw JournalLeaseError.identityChanged }
        }
        try verifyNative(expected)
        let services = try NativeServiceAccountDirectory(accountID: expected.runtime.preparation.accountID, ownerUID: expected.runtime.preparation.ownerUID)
        let mode = try GatewaySettingsNativeSupport.mode(release: candidate, policy: currentCodePolicy)
        let enabled = try GatewaySettingsNativeSupport.serviceActivityEnabled(reference: expected.runtime.state.reference, mode: mode)
        return try prepare(machine: machine, expected: expected, candidate: candidate, directory: directory, admission: admission,
            fileCustodyAccepted: fileCustodyAccepted, verifyCurrent: verifyNative, verifyServices: { plan in
                for claim in plan.claims { try services.validateGroup(claim); try services.validateUser(claim, ownerUID: plan.ownerUID) }
            }, verifyAuthority: { plan in
                let authority = try AccountPreparationController.authorityDirectory(accountID: plan.accountID)
                let directory = authority + "/Key", path = directory + "/" + AuthorityKeyProvisioning.recordFileName
                guard try ProtectedServiceConfiguration.readOptional(anchor: "/",
                    relativePath: String((directory + "/" + AuthorityKeyProvisioningStorage.pendingName).dropFirst()), owner: 0) == nil else {
                    throw AuthorityKeyProvisioningError.conflictingState
                }
                let bytes = try ProtectedServiceConfiguration.read(path: path)
                let retained = try AuthoritySigningKeyRecord.decode(bytes)
                guard retained.macID == plan.macID, retained.accountID == plan.accountID,
                      retained.publicKey == plan.authorityPublicKey else { throw AuthorityRequestSignerError.wrongIdentity }
                try retained.verifyProvisioningHardware()
                guard try ProtectedServiceConfiguration.read(path: path) == bytes else { throw JournalLeaseError.identityChanged }
            }, restoreMaterial: { plan, reference, scope in
                try RuntimeMaterialPreparation.prepareFileIdentity(account: expected.runtime.preparation, services: plan, expected: reference,
                    fileCustodyAccepted: fileCustodyAccepted, serviceActivityEnabled: enabled,
                    selectAuditDelivery: { try RuntimeAuditDeliverySupport.selectedVersion(reference: $0, release: candidate, policy: currentCodePolicy) },
                    verifyCurrent: scope.verify)
            }, validateMaterial: { material, scope in
                try scope.verify()
                let paths = try RuntimePreparationPaths(accountID: expected.runtime.preparation.accountID)
                let bytes = try ProtectedServiceConfiguration.read(path: paths.privateDirectory + "/" + AdministrativeSetupPublication.File.runtimeRecord.name)
                guard try bytes == material.encoded else { throw RuntimePreparationError.conflictingMaterial }
                if let activity = material.serviceActivity {
                    try RuntimeMaterialPreparation.validateServiceActivity(account: expected.runtime.preparation, activity: activity, verifyCurrent: scope.verify)
                }
                try scope.verify()
            })
    }
    static func prepare(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, fileCustodyAccepted: Bool,
        verifyCurrent: @escaping (Snapshot) throws -> Void, verifyServices: @escaping (ServiceAccountPlan) throws -> Void,
        verifyAuthority: @escaping (ServiceAccountPlan) throws -> Void,
        restoreMaterial: (ServiceAccountPlan, RuntimeMaterialReference?, Scope) throws -> RuntimePreparationMaterial,
        validateMaterial: (RuntimePreparationMaterial, Scope) throws -> Void,
        didStage: (RuntimePublicationController.Stage) throws -> Void = { _ in },
        didStorageStage: (PreparationIntentStore.CompletionIntentStorageStage, Scope) throws -> Void = { _, _ in },
        inspectScope: (Scope) throws -> Void = { _ in }) throws -> RuntimePreparationState {
        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        let processID = getpid(), thread = pthread_self()
        var active = true, reading = false, current = expected
        var borrowed: Snapshot?
        var currentVerification: ((Snapshot) throws -> Void)? = verifyCurrent
        var serviceVerification: ((ServiceAccountPlan) throws -> Void)? = verifyServices
        var authorityVerification: ((ServiceAccountPlan) throws -> Void)? = verifyAuthority
        weak var writer = machine
        defer { active = false; writer = nil; borrowed = nil; currentVerification = nil; serviceVerification = nil; authorityVerification = nil }
        func lifetime() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0,
                  active, writer != nil else { throw JournalLeaseError.invalidated }
        }
        func boundary(_ actual: Snapshot) throws {
            try lifetime()
            try admission.validateMachineBoundary(directory: directory, expected: expected.runtime.setup.source.actual.admission.machine)
            try actual.runtime.setup.requireOwner(expected.runtime.setup.owner)
            guard let currentVerification, let serviceVerification, let authorityVerification else { throw JournalLeaseError.invalidated }
            try currentVerification(actual); try serviceVerification(actual.runtime.plan); try authorityVerification(actual.runtime.plan)
            try admission.validateMachineBoundary(directory: directory, expected: expected.runtime.setup.source.actual.admission.machine)
        }
        func read() throws -> MachineUpdateStableRuntimePreparationSnapshot {
            try lifetime()
            guard !reading else { throw PreparationStoreError.transactionActive }
            reading = true; defer { reading = false }
            // The private writer lends its actual frame while it pins all other rows and the catalog.
            if let borrowed { try boundary(borrowed); return borrowed.runtime }
            guard let writer else { throw JournalLeaseError.invalidated }
            try current.requireCurrent(machine: writer, candidate: candidate)
            try boundary(current); try current.requireCurrent(machine: writer, candidate: candidate)
            return current.runtime
        }
        let scope = Scope(read: read, verify: { _ = try read() })
        try scope.verify(); try inspectScope(scope); try scope.verify()
        let material = try restoreMaterial(current.runtime.plan, current.runtime.state.reference, scope)
        let reference = try material.reference
        try current.requireReference(reference)
        try scope.verify(); try didStage(.materialRestored); try scope.verify()
        func verifyMaterial() throws {
            try scope.verify(); try validateMaterial(material, scope); try scope.verify()
        }
        try verifyMaterial()
        guard let writer else { throw JournalLeaseError.invalidated }
        let state = try writer.retainRetainedSetupRuntimeMaterial(reference, expected: current, candidate: candidate,
            directory: directory, admission: admission, fileCustodyAccepted: fileCustodyAccepted) { stage, actual in
                try lifetime()
                guard borrowed == nil else { throw PreparationStoreError.transactionActive }
                if actual.runtime.state == current.runtime.state { try actual.requireSame(as: current) }
                else { try actual.requireRetained(reference, from: current) }
                borrowed = actual; defer { borrowed = nil }
                try verifyMaterial(); try didStorageStage(stage, scope); try verifyMaterial()
            }
        let actual = try writer.retainedSetupMaterialSnapshot(owner: expected.runtime.setup.owner, candidate: candidate)
        try actual.requireRetained(reference, from: current)
        guard actual.runtime.state == state, !state.configurationPublished else { throw RuntimePreparationError.changedScope }
        current = actual; try verifyMaterial(); try didStage(.referenceRetained); try verifyMaterial()
        return state
    }
}
