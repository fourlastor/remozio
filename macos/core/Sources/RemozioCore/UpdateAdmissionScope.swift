import Foundation

enum UpdateAdmissionProvisioningError: Error, Equatable { case invalidScope, missingFile }

/// Account drains remain distinct from the machine replacement boundary. Callers cannot supply paths.
enum UpdateAdmissionScope: Hashable, Sendable {
    case machine
    case account(Data)

    var fileName: String { get throws {
        switch self {
        case .machine: return UpdateAdmissionBarrier.fileName
        case .account(let id):
            guard id.count == 16 else { throw UpdateAdmissionProvisioningError.invalidScope }
            return "update-admission-" + LowercaseHexadecimal.encode(id) + ".lock"
        }
    } }
}
