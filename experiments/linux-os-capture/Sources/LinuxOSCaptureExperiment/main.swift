import Crypto
import Foundation
import Glibc
import RemozioProtocol

func createFile(_ path: Data, _ contents: Data) throws {
    let fd = try OwnedFD(withPath(path) { open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o700) })
    var offset = 0
    while offset < contents.count {
        let count = contents.withUnsafeBytes { write(fd.value, $0.baseAddress!.advanced(by: offset), contents.count - offset) }
        if count < 0 && errno == EINTR { continue }
        try requireObservation(count > 0, .unavailable)
        offset += count
    }
}

func makeDirectory(_ path: Data) throws {
    try requireObservation(try withPath(path) { mkdir($0, 0o700) } == 0, .unavailable)
}

func renamePath(_ source: Data, _ destination: Data) throws {
    try requireObservation(try withPath(source) { a in try withPath(destination) { rename(a, $0) } } == 0, .unavailable)
}

func refuse(_ expected: ObservationError? = nil, _ body: () throws -> Void) throws {
    do { try body() }
    catch let error as ObservationError {
        if let expected { try requireObservation(error == expected, .unavailable) }
        return
    }
    catch is CommandCaptureError {
        try requireObservation(expected == nil, .unavailable)
        return
    }
    throw ObservationError.unavailable
}

final class Fixture {
    let executablePath: Data
    let directoryPath: Data
    let executableBytes: Data
    let pipes: [OwnedFD]
    var descriptors: [Int32] { [pipes[0].value, pipes[3].value, pipes[5].value] }

    init(root: Data, name: String, byteHostile: Bool = false) throws {
        let parent = root + Data(("/" + name).utf8)
        try makeDirectory(parent)
        let suffix = byteHostile ? Data([45, 255, 10]) : Data()
        executablePath = parent + Data("/command".utf8) + suffix
        directoryPath = parent + Data("/cwd".utf8) + suffix
        executableBytes = try Data(contentsOf: URL(fileURLWithPath: "/usr/bin/true"))
        try createFile(executablePath, executableBytes)
        try makeDirectory(directoryPath)
        var owned = [OwnedFD]()
        for _ in 0..<3 {
            var pair: [Int32] = [-1, -1]
            try requireObservation(pipe(&pair) == 0, .unavailable)
            owned.append(try OwnedFD(pair[0])); owned.append(try OwnedFD(pair[1]))
            for fd in pair { try requireObservation(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, .unavailable) }
        }
        pipes = owned
    }
    func capture(_ replacement: [Int32]? = nil) throws -> RetainedOSCapture {
        try .init(executablePath: executablePath, directoryPath: directoryPath,
                  descriptors: replacement ?? descriptors, bindings: SyntheticBindings())
    }
}

var currentCheck = "setup"
do {
    try requireObservation(CommandLine.arguments.count == 2, .invalidPath)
    let root = Data(CommandLine.arguments[1].utf8)
    var checks = [String: Bool]()
    func check(_ name: String, _ body: () throws -> Void) throws {
        currentCheck = name
        try body(); checks[name] = true
    }
    try check("actualCredentialRolesAndTarget") {
        let fixture = try Fixture(root: root, name: "credentials"), retained = try fixture.capture()
        let credentials = try CredentialObservation.current()
        try requireObservation(retained.capture.requester.credentials == credentials.credentials &&
            retained.capture.target.uid == geteuid() && retained.capture.target.gid == getegid() &&
            retained.capture.target.supplementaryGroups == credentials.credentials.supplementaryGroups &&
            retained.capture.target.observedName == nil, .unavailable)
    }
    try check("rawPathBytesAndSchemaRoundTrip") {
        let fixture = try Fixture(root: root, name: "bytes", byteHostile: true), retained = try fixture.capture()
        let decoded = try LinuxCommandCapture(canonicalBytes: retained.capture.canonicalBytes, limits: RetainedOSCapture.limits)
        try requireObservation(decoded.executable.path == fixture.executablePath && decoded.directory.path == fixture.directoryPath &&
            decoded.ioMode == .pipes && decoded.disconnectBehavior == .terminate && decoded.stdioLayout.terminal == nil &&
            decoded.stdioLayout.ptyMask == 0 && decoded.ancestry.completeness == .unavailable && decoded.ancestry.entries.isEmpty &&
            decoded.ancestry.reason == .unsupported && decoded.requester.codePolicyDigest == SyntheticBindings().policy, .unavailable)
        var entered = false
        try retained.withRecheckedFixtureHandoff(decoded) { entered = true }
        try requireObservation(entered, .unavailable)
    }
    try check("boundedHashMatchesBytesAndPreservesOffset") {
        for size in [0, 32768, 32769, 65001] {
            let path = root + Data(("/hash-" + String(size)).utf8)
            let bytes = Data((0..<size).map { UInt8($0 % 251) })
            try createFile(path, bytes)
            let file = try RetainedExecutable(path: path)
            try requireObservation(file.capture.sha256 == Data(SHA256.hash(data: bytes)), .unavailable)
            try requireObservation(lseek(file.descriptor.value, 5, SEEK_SET) == 5, .unavailable)
            try requireObservation(try hashFile(file.descriptor.value) == Data(SHA256.hash(data: bytes)) &&
                lseek(file.descriptor.value, 0, SEEK_CUR) == 5, .unavailable)
        }
    }
    try check("equalBytesDifferentExecutableRejected") {
        let fixture = try Fixture(root: root, name: "replacement"), retained = try fixture.capture()
        let replacement = fixture.executablePath + Data(".new".utf8)
        try createFile(replacement, fixture.executableBytes)
        try renamePath(replacement, fixture.executablePath)
        try refuse(.changedObject) { try retained.withRecheckedFixtureHandoff(retained.capture) { throw ObservationError.unavailable } }
    }
    try check("sameInodeContentMutationRejected") {
        let fixture = try Fixture(root: root, name: "content"), retained = try fixture.capture()
        let writer = try OwnedFD(withPath(fixture.executablePath) { open($0, O_WRONLY | O_CLOEXEC) })
        var byte: UInt8 = fixture.executableBytes[4] ^ 1
        try requireObservation(pwrite(writer.value, &byte, 1, 4) == 1, .unavailable)
        try refuse(.changedObject) { try retained.withRecheckedFixtureHandoff(retained.capture) { throw ObservationError.unavailable } }
    }
    try check("pathReplacementDuringHashRejected") {
        let fixture = try Fixture(root: root, name: "hash-race"), retained = try fixture.capture()
        let parent = root + Data("/hash-race".utf8), replacement = root + Data("/hash-race-new".utf8)
        try makeDirectory(replacement)
        try createFile(replacement + Data("/command".utf8), fixture.executableBytes)
        try refuse(.changedObject) {
            try retained.executable.recheck(afterNamedHashForTesting: {
                // Renaming the parent keeps the retained file's ctime unchanged, so only a fresh name lookup can reject.
                try renamePath(parent, parent + Data(".old".utf8))
                try renamePath(replacement, parent)
                try requireObservation(try FileObservation(retained.executable.descriptor.value) == retained.executable.observation, .unavailable)
            })
        }
    }
    try check("kernelExecutableObjectMustMatchPath") {
        let fixture = try Fixture(root: root, name: "kernel-object")
        let kernelObject = try OwnedFD(open("/proc/thread-self/exe", O_RDONLY | O_CLOEXEC))
        try refuse(.changedObject) { _ = try RetainedExecutable(path: fixture.executablePath, retainedDescriptor: kernelObject) }
    }
    try check("directoryReplacementRejected") {
        let fixture = try Fixture(root: root, name: "directory"), retained = try fixture.capture()
        try renamePath(fixture.directoryPath, fixture.directoryPath + Data(".old".utf8))
        try makeDirectory(fixture.directoryPath)
        try refuse(.changedObject) { try retained.withRecheckedFixtureHandoff(retained.capture) { throw ObservationError.unavailable } }
    }
    try check("directoryContentChangeAllowed") {
        let fixture = try Fixture(root: root, name: "directory-content"), retained = try fixture.capture()
        try createFile(fixture.directoryPath + Data("/new-file".utf8), Data([1]))
        try retained.withRecheckedFixtureHandoff(retained.capture) {}
    }
    try check("sharedPipeFlagMutationRejected") {
        let fixture = try Fixture(root: root, name: "pipe-flags"), retained = try fixture.capture()
        let fd = fixture.descriptors[0], flags = fcntl(fd, F_GETFL)
        try requireObservation(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, .unavailable)
        try refuse(.changedStream) { try retained.withRecheckedFixtureHandoff(retained.capture) { throw ObservationError.unavailable } }
        try requireObservation(fcntl(fd, F_SETFL, flags) == 0, .unavailable)
        try refuse(.retired) { try retained.withRecheckedFixtureHandoff(retained.capture) { throw ObservationError.unavailable } }
    }
    try check("fileKindAccessAndAppendMutation") {
        let fixture = try Fixture(root: root, name: "file-flags")
        let path = fixture.directoryPath + Data("/output".utf8)
        try createFile(path, Data())
        let fd = try OwnedFD(withPath(path) { open($0, O_WRONLY | O_APPEND | O_CLOEXEC) })
        let retained = try fixture.capture([fixture.descriptors[0], fd.value, fixture.descriptors[2]])
        try requireObservation(retained.capture.stdioLayout.output.source.kind == .file &&
            retained.capture.stdioLayout.output.access == .writeOnly && retained.capture.stdioLayout.output.flags == [.append], .unavailable)
        try retained.withRecheckedFixtureHandoff(retained.capture) {}
        let flags = fcntl(fd.value, F_GETFL)
        try requireObservation(flags >= 0 && fcntl(fd.value, F_SETFL, flags & ~O_APPEND) == 0, .unavailable)
        try refuse(.changedStream) { try retained.withRecheckedFixtureHandoff(retained.capture) { throw ObservationError.unavailable } }
    }
    try check("retainedDuplicateSurvivesOriginalReuse") {
        let fixture = try Fixture(root: root, name: "reuse"), retained = try fixture.capture()
        let replacement = try OwnedFD(open("/dev/null", O_RDONLY | O_CLOEXEC))
        try requireObservation(dup2(replacement.value, fixture.descriptors[0]) == fixture.descriptors[0], .unavailable)
        try retained.withRecheckedFixtureHandoff(retained.capture) {}
    }
    try check("descriptorShapeAndAccessRejected") {
        let fixture = try Fixture(root: root, name: "descriptors")
        try refuse(.invalidDescriptor) { _ = try fixture.capture([-1, fixture.descriptors[1], fixture.descriptors[2]]) }
        try refuse(.invalidDescriptor) { _ = try fixture.capture([]) }
        try refuse { _ = try fixture.capture([fixture.pipes[1].value, fixture.pipes[3].value, fixture.pipes[5].value]) }
        try refuse { _ = try fixture.capture([fixture.pipes[0].value, fixture.pipes[2].value, fixture.pipes[5].value]) }
    }
    try check("unsupportedKernelObjectsAndFlagsRejected") {
        let fixture = try Fixture(root: root, name: "unsupported")
        let directory = try OwnedFD(withPath(fixture.directoryPath) { open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC) })
        let device = try OwnedFD(open("/dev/null", O_RDONLY | O_CLOEXEC))
        let socket = try OwnedFD(Glibc.socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0))
        for fd in [directory.value, device.value, socket.value] {
            try refuse(.unsupportedObject) { _ = try fixture.capture([fd, fixture.descriptors[1], fixture.descriptors[2]]) }
        }
        // Linux O_PATH is not exported by every Swift Glibc module; its ABI value is fixed on this x86_64 fixture.
        let pathOnly = try OwnedFD(withPath(fixture.executablePath) { open($0, Int32(0o10000000) | O_CLOEXEC) })
        try refuse(.unsupportedFlags) { _ = try fixture.capture([pathOnly.value, fixture.descriptors[1], fixture.descriptors[2]]) }
    }
    try check("credentialParserPreservesRolesAndRefusesUnsupported") {
        let prefix = "Uid:\t1000\t1000\t2000\t3000\nGid:\t4000\t4000\t5000\t6000\nGroups:\t9 7\n"
        let value = try CredentialObservation.parse(Data(prefix.utf8))
        try requireObservation(value.credentials.savedUID == 2000 && value.credentials.filesystemUID == 3000 &&
            value.credentials.savedGID == 5000 && value.credentials.filesystemGID == 6000 && value.credentials.supplementaryGroups == [7, 9], .unavailable)
        try refuse(.unsupportedCredentials) { try value.requireOrdinaryAccount() }
        let duplicateGroups = try CredentialObservation.parse(Data(prefix.replacingOccurrences(of: "9 7", with: "9 7 9").utf8))
        try requireObservation(duplicateGroups.credentials.supplementaryGroups == [7, 9] &&
            duplicateGroups.observedSupplementaryGroups == [9, 7, 9], .unavailable)
        for invalid in [prefix + "Uid:\t1 1 1 1\n", prefix.replacingOccurrences(of: "2000", with: "4294967296"),
                        prefix.replacingOccurrences(of: "2000", with: "-2"), prefix.replacingOccurrences(of: "9 7", with: "9 x"),
                        prefix.replacingOccurrences(of: "Groups:\t9 7\n", with: ""), prefix.replacingOccurrences(of: "2000\t", with: "")] {
            try refuse(.malformedCredentials) { _ = try CredentialObservation.parse(Data(invalid.utf8)) }
        }
    }
    try check("captureMismatchBlocksHandoff") {
        let first = try Fixture(root: root, name: "first").capture()
        let second = try Fixture(root: root, name: "second").capture()
        try refuse(.captureMismatch) { try first.withRecheckedFixtureHandoff(second.capture) { throw ObservationError.unavailable } }
    }
    try check("pathSubstitutionAndInvalidBytesRejected") {
        let fixture = try Fixture(root: root, name: "path")
        try refuse(.invalidPath) { _ = try RetainedExecutable(path: Data("relative".utf8)) }
        try refuse(.invalidPath) { _ = try RetainedExecutable(path: fixture.executablePath + Data([0])) }
        let link = fixture.executablePath + Data(".link".utf8)
        try requireObservation(try withPath(fixture.executablePath) { target in try withPath(link) { symlink(target, $0) } } == 0, .unavailable)
        try refuse(.invalidDescriptor) { _ = try RetainedExecutable(path: link) }
    }
    let report: [String: Any] = ["passed": true, "checks": checks, "observations": [
        "productionAuthority": false, "productionAdmission": false, "trustedCode": false,
        "syntheticCallerBindings": true, "syntheticCodePolicyDigest": true, "selfObservationOnly": true,
        "actualCredentialTransitionTested": false, "physicalPhone": false, "hardwareKeys": false,
        "commandsExecuted": 0, "schemaVersion": 4,
    ]]
    let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
} catch {
    // Never emit OS paths, identifiers, command content, environment or native error descriptions.
    let failure = ["passed": false, "failedCheck": currentCheck, "reason": (error as? ObservationError)?.rawValue ?? "codecOrFixtureFailure"] as [String: Any]
    if let data = try? JSONSerialization.data(withJSONObject: failure, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data + Data([10]))
    }
    exit(1)
}
