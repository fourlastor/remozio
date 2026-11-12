import Darwin
import Foundation

/// Uses owned protected directories only. The native adapter remains part of the E01/G9 design.
enum MachineUpdateRetainedSetupPromotionFiles {
    typealias Publication = RuntimeRetainedSetupCompletionPublication
    typealias Verify = () throws -> Void

    static func readInLease(_ publication: Publication, file: Publication.File, directory: ProtectedSetupDirectory,
        owner: uid_t, verify: Verify) throws -> Data {
        try requireOwned(owner)
        let selected = try artifact(publication, file: file)
        try verify(); try directory.validate()
        let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: selected.file.name,
            owner: owner, privateFile: selected.file.mode == 0o600)
        try AdministrativeSetupPublication.validateRetained(bytes, file: selected.file, directory: directory,
            owner: owner, verify: verify)
        guard bytes == selected.previous || bytes == selected.selected else { throw RuntimeActivationError.changedScope }
        try verify(); return bytes
    }

    static func replaceInLease(_ publication: Publication, file: Publication.File, directory: ProtectedSetupDirectory,
        owner: uid_t, verify: Verify,
        didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        try requireOwned(owner)
        let selected = try artifact(publication, file: file)
        try verify()
        try AdministrativeSetupPublication.replaceMachineUpdateConfiguration(selected.selected, expected: selected.previous,
            file: selected.file, directory: directory, owner: owner, verify: verify, didStage: didStage)
        try verify()
        guard try readInLease(publication, file: file, directory: directory, owner: owner, verify: verify) == selected.selected else {
            throw RuntimeActivationError.changedScope
        }
    }

    static func retainSelectedInLease(_ publication: Publication, file: Publication.File, directory: ProtectedSetupDirectory,
        owner: uid_t, verify: Verify) throws {
        try requireOwned(owner)
        let selected = try artifact(publication, file: file)
        guard try readInLease(publication, file: file, directory: directory, owner: owner, verify: verify) == selected.selected else {
            throw RuntimeActivationError.incomplete
        }
        try AdministrativeSetupPublication.retainMachineUpdateConfiguration(selected.selected, file: selected.file,
            directory: directory, owner: owner, verify: verify)
        guard try readInLease(publication, file: file, directory: directory, owner: owner, verify: verify) == selected.selected else {
            throw RuntimeActivationError.changedScope
        }
    }

    private static func requireOwned(_ owner: uid_t) throws {
        guard owner != 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
    }
    private static func artifact(_ publication: Publication, file: Publication.File) throws -> Publication.Artifact {
        guard publication.artifacts.map(\.kind) == Publication.File.allCases,
              let selected = publication.artifacts.first(where: { $0.kind == file }) else { throw RuntimeActivationError.invalidPlan }
        try selected.file.validate(); return selected
    }
}
