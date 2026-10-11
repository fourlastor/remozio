import AppKit
import CryptoKit
import Darwin
import Foundation
import Sparkle

enum ProbeFailure: Error { case configuration, ownership, input, deadline }

func frame(_ event: String, _ fields: [String: Any] = [:]) {
    var value = fields; value["event"] = event
    guard let bytes = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { exit(70) }
    FileHandle.standardOutput.write(bytes + Data([10]))
}

func ownedRoot(_ path: String) throws -> URL {
    let root = URL(fileURLWithPath: path).standardizedFileURL
    guard getuid() != 0, geteuid() == getuid(), root.path == root.resolvingSymlinksInPath().path,
          root.lastPathComponent.hasPrefix("remozio-sparkle-boundary-") else { throw ProbeFailure.configuration }
    var metadata = stat()
    guard lstat(root.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR,
          metadata.st_uid == geteuid(), metadata.st_mode & 0o077 == 0 else { throw ProbeFailure.ownership }
    return root
}

func fixtureBundle(_ root: URL) throws -> Bundle {
    let bundle = Bundle.main
    let prefix = root.path + "/", path = bundle.bundleURL.standardizedFileURL.path
    guard path.hasPrefix(prefix), path == bundle.bundleURL.resolvingSymlinksInPath().path,
          bundle.bundleIdentifier?.hasPrefix("dev.remozio.experiment.sparkleboundary.") == true,
          bundle.object(forInfoDictionaryKey: "SUEnableInstallerLauncherService") as? Bool == false,
          bundle.object(forInfoDictionaryKey: "SUEnableDownloaderService") as? Bool == false,
          bundle.object(forInfoDictionaryKey: "SUEnableAutomaticChecks") as? Bool == false,
          bundle.object(forInfoDictionaryKey: "SUAutomaticallyUpdate") as? Bool == true,
          bundle.object(forInfoDictionaryKey: "SUAllowsAutomaticUpdates") as? Bool == true,
          bundle.object(forInfoDictionaryKey: "SURequireSignedFeed") as? Bool == true,
          bundle.object(forInfoDictionaryKey: "SUVerifyUpdateBeforeExtraction") as? Bool == true,
          bundle.object(forInfoDictionaryKey: "SUSignedFeedFailureExpirationInterval") as? Int == 0,
          let feed = bundle.object(forInfoDictionaryKey: "SUFeedURL") as? String,
          let url = URL(string: feed), url.scheme == "http", url.host == "127.0.0.1", url.port != nil,
          url.path == "/feed.xml", url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
        throw ProbeFailure.configuration
    }
    var metadata = stat()
    guard lstat(path, &metadata) == 0, metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFDIR,
          access(path, W_OK) == 0 else { throw ProbeFailure.ownership }
    return bundle
}

// Only the parent harness sees these synthetic callbacks. No prompt is displayed or accepted.
@MainActor final class QuietDriver: NSObject, SPUUserDriver {
    private func unexpected(_ callback: String = #function) { frame("unexpected-user-driver", ["callback": callback]); exit(65) }
    func show(_ request: SPUUpdatePermissionRequest, reply: @escaping (SUUpdatePermissionResponse) -> Void) { unexpected() }
    func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) { unexpected() }
    func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) { unexpected() }
    func showUpdateReleaseNotes(with downloadData: SPUDownloadData) { unexpected() }
    func showUpdateReleaseNotesFailedToDownloadWithError(_ error: any Error) { unexpected() }
    func showUpdateNotFoundWithError(_ error: any Error, acknowledgement: @escaping () -> Void) { unexpected() }
    func showUpdaterError(_ error: any Error, acknowledgement: @escaping () -> Void) { frame("updater-error", ["code": (error as NSError).code]); exit(65) }
    func showDownloadInitiated(cancellation: @escaping () -> Void) { unexpected() }
    func showDownloadDidReceiveExpectedContentLength(_ length: UInt64) { unexpected() }
    func showDownloadDidReceiveData(ofLength length: UInt64) { unexpected() }
    func showDownloadDidStartExtractingUpdate() { unexpected() }
    func showExtractionReceivedProgress(_ progress: Double) { unexpected() }
    func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) { unexpected() }
    func showInstallingUpdate(withApplicationTerminated terminated: Bool, retryTerminatingApplication: @escaping () -> Void) { unexpected() }
    func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) { acknowledgement() }
    func dismissUpdateInstallation() {}
}

@MainActor final class Controller: NSObject, NSApplicationDelegate, SPUUpdaterDelegate {
    let bundle: Bundle
    let driver = QuietDriver()
    var updater: SPUUpdater?
    var immediate: (() -> Void)?
    var postponed: (() -> Void)?
    init(bundle: Bundle) { self.bundle = bundle }
    func applicationDidFinishLaunching(_ notification: Notification) {
        do {
            let updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: driver, delegate: self)
            self.updater = updater
            try updater.start()
            updater.automaticallyDownloadsUpdates = true
            guard updater.allowsAutomaticUpdates, updater.automaticallyDownloadsUpdates else { throw ProbeFailure.configuration }
            frame("started", ["pid": getpid()])
            FileHandle.standardInput.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                Task { @MainActor in self?.command(data) }
            }
            updater.checkForUpdatesInBackground()
        } catch { frame("startup-failed", ["code": (error as NSError).code]); exit(65) }
    }
    func command(_ data: Data) {
        switch String(decoding: data, as: UTF8.self) {
        case "resume\n":
            guard let callback = immediate else { frame("wrong-command-state"); exit(65) }
            immediate = nil; callback()
        case "release\n":
            guard let callback = postponed else { frame("wrong-command-state"); exit(65) }
            postponed = nil; callback()
        case "exit\n": frame("fixture-exiting"); exit(0)
        default: frame("invalid-command"); exit(65)
        }
    }
    func updater(_ updater: SPUUpdater, didFinishLoading appcast: SUAppcast) {
        guard appcast.signingValidationStatus == .succeeded else { frame("unverified-feed"); exit(65) }
        frame("verified-feed")
    }
    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate item: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        guard item.versionString == "2", item.signingValidationStatus == .succeeded else { throw ProbeFailure.configuration }
    }
    func updater(_ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem, immediateInstallationBlock callback: @escaping () -> Void) -> Bool {
        guard immediate == nil else { frame("duplicate-preparation"); exit(65) }
        immediate = callback; frame("prepared-on-quit"); return true
    }
    func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem, untilInvokingBlock callback: @escaping () -> Void) -> Bool {
        guard postponed == nil else { frame("duplicate-postponement"); exit(65) }
        postponed = callback; frame("postponed"); return true
    }
    func updater(_ updater: SPUUpdater, willInstallUpdate item: SUAppcastItem) { frame("will-install") }
    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: (any Error)?) {
        if let error { frame("cycle-failed", ["code": (error as NSError).code]); exit(65) }
    }
}

func signFeed(root: URL, archiveURL: String) throws {
    guard let url = URL(string: archiveURL), url.scheme == "http", url.host == "127.0.0.1", url.port != nil,
          url.path == "/update.zip", url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
        throw ProbeFailure.configuration
    }
    let key = Curve25519.Signing.PrivateKey()
    frame("public-key", ["key": key.publicKey.rawRepresentation.base64EncodedString()])
    guard try FileHandle.standardInput.read(upToCount: 5) == Data("sign\n".utf8) else { throw ProbeFailure.input }
    let archive = root.appendingPathComponent("update.zip")
    var metadata = stat()
    guard lstat(archive.path, &metadata) == 0, metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_nlink == 1, metadata.st_size > 0, metadata.st_size <= 100_000_000 else { throw ProbeFailure.ownership }
    let bytes = try Data(contentsOf: archive)
    let feed = Data("""
    <?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Disposable boundary probe</title>
    <item><title>Fixture 2</title><sparkle:version>2</sparkle:version><sparkle:shortVersionString>0.2.0</sparkle:shortVersionString>
    <enclosure url="\(archiveURL)" length="\(bytes.count)" type="application/octet-stream" sparkle:edSignature="\(try key.signature(for: bytes).base64EncodedString())" /></item>
    </channel></rss>
    """.utf8)
    let signed = feed + Data("<!-- sparkle-signatures:\nedSignature: \(try key.signature(for: feed).base64EncodedString())\nlength: \(feed.count)\n-->\n".utf8)
    try signed.write(to: root.appendingPathComponent("feed.xml"), options: .withoutOverwriting)
    frame("feed-signed")
}

@MainActor func run() throws {
    let args = CommandLine.arguments
    if args.count == 1, Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String == "2" {
        let root = try ownedRoot(Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().path)
        _ = try fixtureBundle(root)
        try Data("2\n".utf8).write(to: root.appendingPathComponent("relaunch-observed"), options: .withoutOverwriting)
        frame("relaunched-version2"); return
    }
    guard args.count >= 3 else { throw ProbeFailure.configuration }
    let root = try ownedRoot(args[2])
    var input = stat()
    guard fstat(STDIN_FILENO, &input) == 0, input.st_mode & S_IFMT == S_IFIFO else { throw ProbeFailure.input }
    if args[1] == "signer" {
        guard args.count == 4 else { throw ProbeFailure.configuration }
        try signFeed(root: root, archiveURL: args[3]); return
    }
    guard args[1] == "run", args.count == 3 else { throw ProbeFailure.configuration }
    let bundle = try fixtureBundle(root)
    guard bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String == "1" else { throw ProbeFailure.configuration }
    let application = NSApplication.shared
    application.setActivationPolicy(.prohibited)
    let controller = Controller(bundle: bundle)
    application.delegate = controller
    withExtendedLifetime(controller) { application.run() }
}

do { try MainActor.assumeIsolated { try run() } }
catch { frame("probe-failed"); exit(65) }
