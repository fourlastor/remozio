import Darwin
import Foundation
import RemozioMach
import Security

/// Observes one original process without acquiring signal or wait authority.
protocol RuntimeJobExitWitness: AnyObject {
    var processID: pid_t { get }
    func hasExited() throws -> Bool
}

/// A serialized stop session retains this witness until the original process has an exit event.
final class RuntimeJobProcessObservation: RuntimeJobExitWitness {
    let processID: pid_t
    private let token: audit_token_t
    private let expectedUID: uid_t
    private let expectedParent: pid_t
    private let expectedPath: Data
    private var observer: OpaquePointer?
    private let ownerPID = getpid()

    static func open(job: InstalledAccountJobManifest, code: AuthorityCodeEntry, processID: pid_t) throws -> RuntimeJobProcessObservation {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard code.active, code.role == job.declaration.role else { throw RuntimeActivationError.changedScope }
        let policy = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
            approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: job.declaration.executionUID)
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(policy.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement else { throw RuntimeActivationError.unavailable }
        return try .init(processID: processID, expectedUID: job.declaration.executionUID,
            expectedParent: 1, expectedPath: Data(job.executablePath.utf8), validateCode: { token in
                var token = token
                let data = withUnsafeBytes(of: &token) { Data($0) }
                var guest: SecCode?
                guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &guest) == errSecSuccess,
                      let guest, SecCodeCheckValidity(guest, [], requirement) == errSecSuccess else {
                    throw RuntimeActivationError.changedScope
                }
            })
    }
    // Ordinary-owner fixture seam. Native entry fixes launchd parent, path, UID and signed code policy.
    init(processID: pid_t, expectedUID: uid_t, expectedParent: pid_t, expectedPath: Data,
         validateCode: (audit_token_t) throws -> Void) throws {
        guard processID > 1, expectedParent > 0, expectedPath.first == 0x2f else { throw RuntimeActivationError.unavailable }
        self.processID = processID; self.expectedUID = expectedUID; self.expectedParent = expectedParent; self.expectedPath = expectedPath
        let first = try CommandAncestryObservation.sample(processID)
        token = first.token
        try requireBinding(first); try validateCode(first.token)
        var value = first.token
        let result = remozio_command_caller_observer_create(&value, &observer)
        guard result == 0, observer != nil else { throw RuntimeActivationError.unavailable }
        do {
            let checked = try CommandAncestryObservation.sample(processID)
            try requireBinding(checked); try validateCode(checked.token)
        } catch { remozio_command_caller_observer_close(observer); observer = nil; throw error }
    }
    private func requireBinding(_ sample: CommandAncestryObservation.Process) throws {
        guard CommandAncestryObservation.sameToken(sample.token, token), sample.pid == processID,
              audit_token_to_euid(sample.token) == expectedUID, audit_token_to_ruid(sample.token) == expectedUID,
              sample.parentPID == expectedParent, sample.path == expectedPath else { throw RuntimeActivationError.changedScope }
    }
    func hasExited() throws -> Bool {
        guard getpid() == ownerPID, let observer else { throw RuntimeActivationError.unavailable }
        var state = REMOZIO_CALLER_UNCHANGED
        guard remozio_command_caller_observer_poll(observer, &state) == 0 else { throw RuntimeActivationError.unavailable }
        switch state {
        case REMOZIO_CALLER_EXITED: return true
        case REMOZIO_CALLER_UNCHANGED:
            // Failure to read a live binding is unknown, never proof of exit.
            try requireBinding(CommandAncestryObservation.sample(processID)); return false
        default: throw RuntimeActivationError.unavailable
        }
    }
    deinit { remozio_command_caller_observer_close(observer) }
}
