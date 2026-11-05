import Foundation

/// Joins the shared replacement gate with an optional account drain. Activity references protect existing work separately.
final class UpdateAdmissionBoundary: Sendable {
    private let machine: UpdateAdmissionBarrier
    private let account: UpdateAdmissionBarrier?
    private let verifyAdmission: (@Sendable () throws -> Void)?
    var accountID: Data? {
        if case .account(let id)? = account?.scope { return id }
        return nil
    }
    init(machine: UpdateAdmissionBarrier, account: UpdateAdmissionBarrier? = nil,
         verifyAdmission: (@Sendable () throws -> Void)? = nil) throws {
        guard machine.scope == .machine else { throw ApprovalCoordinatorError.invalidConfiguration }
        if let account {
            guard case .account = account.scope else { throw ApprovalCoordinatorError.invalidConfiguration }
        }
        self.machine = machine; self.account = account; self.verifyAdmission = verifyAdmission
        try validate()
    }
    func validate() throws { try machine.validate(); try account?.validate() }
    func beginAccountDrain() throws -> UpdateDrainToken {
        try validate()
        guard let account else { throw ApprovalCoordinatorError.invalidConfiguration }
        return try account.beginDrain()
    }
    func acquireAdmission() throws -> UpdateAdmissionLease {
        try validate(); try verifyAdmission?()
        let global = try machine.acquireAdmission()
        var scoped: UpdateAdmissionToken?
        do {
            scoped = try account?.acquireAdmission()
            try global.validate(); try scoped?.validate(); try verifyAdmission?()
            try global.validate(); try scoped?.validate()
            return .init(tokens: [global] + (scoped.map { [$0] } ?? []))
        } catch { scoped?.close(); global.close(); throw error }
    }
}

/// Retains both gates only through request creation. It cannot prove quiescence or authorize activation.
final class UpdateAdmissionLease: Sendable {
    private let tokens: [UpdateAdmissionToken]
    fileprivate init(tokens: [UpdateAdmissionToken]) { self.tokens = tokens }
    func validate() throws { for token in tokens { try token.validate() } }
    func close() { for token in tokens.reversed() { token.close() } }
    deinit { close() }
}
