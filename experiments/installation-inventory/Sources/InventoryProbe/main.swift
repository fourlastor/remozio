import Darwin
import Foundation
@testable import RemozioCore

struct ProbeFailure: Error { let stage: String }
func require(_ ok: Bool, _ stage: String) throws { if !ok { throw ProbeFailure(stage: stage) } }
func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
func inventory(_ path: String) throws -> InstallationInventory {
    try .init(macID: id(1), installationID: id(2), revision: id(4), bundlePath: path,
        releaseDigest: Data(repeating: 9, count: 32), accounts: [.init(accountID: id(3), ownerUID: getuid())],
        services: [.init(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
            label: "dev.remozio.fixture.authority", plistName: "dev.remozio.fixture.authority.plist", accountID: id(3))])
}
func store(_ root: String, initialize: Bool = false, didCommit: (() throws -> Void)? = nil) throws -> PreparationIntentStore {
    try .init(lease: InstallationStorageLease(anchor: root, relativeDirectory: "State", owner: geteuid()),
        macID: id(1), maximumRecords: 2, initialize: initialize, didCommit: didCommit)
}
func executablePath() throws -> String {
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var bytes = [CChar](repeating: 0, count: Int(size))
    try require(_NSGetExecutablePath(&bytes, &size) == 0, "executable-path")
    return String(cString: bytes)
}
final class ChildOwner {
    let process: Process
    init(_ process: Process) { self.process = process }
    deinit { stop() }
    func stop() {
        if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
    }
}
func runChild(_ mode: String, _ root: String) throws -> ChildOwner {
    let child = Process(); child.executableURL = URL(fileURLWithPath: try executablePath())
    child.arguments = [mode, root]; try child.run(); return ChildOwner(child)
}
func wait(_ owner: ChildOwner, expected: Int32) throws {
    let child = owner.process
    defer { withExtendedLifetime(owner) {} }
    let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
    while child.isRunning, DispatchTime.now().uptimeNanoseconds < deadline { usleep(10_000) }
    if child.isRunning { kill(child.processIdentifier, SIGKILL); child.waitUntilExit(); throw ProbeFailure(stage: "child-timeout") }
    child.waitUntilExit(); try require(child.terminationReason == .exit && child.terminationStatus == expected, "child-exit")
}
guard getuid() != 0, geteuid() == getuid() else { throw ProbeFailure(stage: "ordinary-owner-only") }
if CommandLine.arguments.count == 3 {
    let parent = getppid(), group = getpgid(parent)
    try require(parent > 1 && group > 0 && setpgid(0, group) == 0 && getpgrp() == group, "runner-process-group")
    let mode = CommandLine.arguments[1], root = CommandLine.arguments[2]
    if mode == "writer-busy" {
        do { let unexpected = try store(root); try unexpected.close(); exit(90) }
        catch JournalLeaseError.busy { exit(0) }
    }
    if mode == "commit-exit" {
        let current = try store(root)
        let retained = try current.inventory()!
        _ = try current.writeInventory(inventory("/Library/Remozio/AfterExit.app"), expectedRevision: retained.revision)
        _exit(23)
    }
    if mode == "commit-kill" {
        let ready = FileHandle.standardOutput
        let current = try store(root, didCommit: {
            var byte: UInt8 = 1
            try require(write(ready.fileDescriptor, &byte, 1) == 1, "commit-ready")
            while true { pause() }
        })
        let retained = try current.inventory()!
        _ = try current.writeInventory(inventory("/Library/Remozio/AfterKill.app"), expectedRevision: retained.revision)
        exit(91)
    }
    throw ProbeFailure(stage: "mode")
}
try require(CommandLine.arguments.count == 1, "arguments")
let root = "/private/tmp/remozio-production-inventory-" + UUID().uuidString
try require(mkdir(root, 0o700) == 0, "private-root")
try require(chmod(root, 0o700) == 0, "root-mode")
defer { try? FileManager.default.removeItem(atPath: root) }
for (name, mode) in [("State", mode_t(0o700)), ("Target", mode_t(0o755))] {
    let path = root + "/" + name
    try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
    try require(chmod(path, mode) == 0, "directory-mode")
}
for name in ["writer.lock", "installation.sqlite"] {
    let path = root + "/State/" + name
    try Data().write(to: URL(fileURLWithPath: path)); try require(chmod(path, 0o600) == 0, "file-mode")
}
let initial = try store(root, initialize: true)
try initial.upgradeInventoryStorage()
let first = try initial.writeInventory(inventory("/Library/Remozio/Initial.app"), expectedRevision: nil)
let target = try ReleaseDestinationLease(anchor: root, relativeDirectory: "Target", owner: geteuid())
let preparation = try initial.begin(parent: target.path, ancestry: target.preparationAncestry())
target.close()
try wait(runChild("writer-busy", root), expected: 0)
try initial.close()
try wait(runChild("commit-exit", root), expected: 23)
let reopened = try store(root)
let afterExit = try reopened.inventory()
try require(afterExit != nil, "exit-record-present")
let exitRecord = afterExit!
try require(exitRecord.bundlePath == "/Library/Remozio/AfterExit.app" && exitRecord.revision != first.revision, "exit-retained")
try require(try reopened.records() == [preparation], "exit-preparation")
try reopened.close()
let child = Process(), pipe = Pipe()
child.executableURL = URL(fileURLWithPath: try executablePath()); child.arguments = ["commit-kill", root]
child.standardOutput = pipe; try child.run(); let ownedChild = ChildOwner(child)
pipe.fileHandleForWriting.closeFile()
defer { ownedChild.stop(); pipe.fileHandleForReading.closeFile() }
var descriptor = pollfd(fd: pipe.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
let ready = poll(&descriptor, 1, 5000)
var byte: UInt8 = 0
let count = ready == 1 ? read(descriptor.fd, &byte, 1) : -1
let childInRunnerGroup = getpgid(child.processIdentifier) == getpgrp()
let killed = kill(child.processIdentifier, SIGKILL); child.waitUntilExit(); pipe.fileHandleForReading.closeFile()
try require(ready == 1 && count == 1 && byte == 1 && killed == 0 && childInRunnerGroup, "kill-after-commit")
try require(child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGKILL, "kill-observed")
let final = try store(root)
let afterKill = try final.inventory()
try require(afterKill != nil, "kill-record-present")
let killedRecord = afterKill!
try require(killedRecord.bundlePath == "/Library/Remozio/AfterKill.app" && killedRecord.revision != exitRecord.revision, "kill-retained")
try require(try final.records() == [preparation], "kill-preparation")
try final.close()
try FileManager.default.removeItem(atPath: root)
try require(!FileManager.default.fileExists(atPath: root), "fixture-cleanup")
let result: [String: Any] = ["evidenceFormat": 1, "ordinaryOwner": true, "productionStoreImplementation": true,
    "internalLeaseSeam": true, "childrenJoinedRunnerGroup": true, "crossProcessWriterExclusion": true, "exitWithoutFinalizersRetained": true,
    "killAfterCommitRetained": true, "preparationRecordsPreserved": true, "fixtureRemoved": true, "rootIsolationProven": false,
    "powerLossProven": false, "nativeIOFaultProven": false, "servicesRegistered": false,
    "OS": ProcessInfo.processInfo.operatingSystemVersionString]
print(String(decoding: try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
