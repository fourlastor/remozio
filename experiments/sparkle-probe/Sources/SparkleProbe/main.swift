import AppKit
import CryptoKit
import Foundation
import Sparkle

// This executable has no install entry point. Every host bundle and key is disposable.
@MainActor final class Probe: NSObject, SPUUpdaterDelegate {
    var updater: SPUUpdater?
    var finished = false
    var found: String?
    var signatureValid = false
    var selectionChecks = 0
    var frameworkError = false
    var errorCode: Int?

    func updater(_ updater: SPUUpdater, mayPerform updateCheck: SPUUpdateCheck) throws {
        guard updateCheck == .updateInformation else { throw NSError(domain: "RemozioProbe", code: 1) }
    }
    func updater(_ updater: SPUUpdater, didFinishLoading appcast: SUAppcast) {
        signatureValid = appcast.signingValidationStatus == .succeeded
    }
    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate item: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        selectionChecks += 1
        guard updateCheck == .updateInformation, item.signingValidationStatus == .succeeded else {
            throw NSError(domain: "RemozioProbe", code: 2)
        }
    }
    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) { found = item.versionString }
    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: (any Error)?) {
        errorCode = error.map { ($0 as NSError).code }
        frameworkError = error.map { ($0 as NSError).domain == SUSparkleErrorDomain } ?? false
        finished = true
    }
}

@MainActor func run() throws {
    let arguments = CommandLine.arguments
    guard (3...4).contains(arguments.count) else { throw NSError(domain: "usage: SparkleProbe prepare|probe path", code: 1) }
    let root = URL(fileURLWithPath: arguments[2], isDirectory: true)
    if arguments[1] == "prepare" {
        guard arguments.count == 4, URL(string: arguments[3])?.host == "127.0.0.1" else {
            throw NSError(domain: "Expected loopback archive sentinel", code: 1)
        }
        let key = Curve25519.Signing.PrivateKey()
        let feed = Data("""
        <?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Disposable probe</title>
        <item><title>Fixture 2</title><sparkle:version>2</sparkle:version><sparkle:shortVersionString>0.2.0</sparkle:shortVersionString>
        <enclosure url="\(arguments[3])" length="1" type="application/octet-stream" sparkle:edSignature="\(Data(repeating: 0, count: 64).base64EncodedString())" /></item>
        </channel></rss>
        """.utf8)
        let signature = try key.signature(for: feed).base64EncodedString()
        let signed = feed + Data("<!-- sparkle-signatures:\nedSignature: \(signature)\nlength: \(feed.count)\n-->\n".utf8)
        try signed.write(to: root.appendingPathComponent("valid.xml"))
        try feed.write(to: root.appendingPathComponent("unsigned.xml"))
        try Data(String(decoding: signed, as: UTF8.self).replacingOccurrences(of: "Fixture 2", with: "Fixture X").utf8)
            .write(to: root.appendingPathComponent("tampered.xml"))
        let other = Curve25519.Signing.PrivateKey()
        let wrong = feed + Data("<!-- sparkle-signatures:\nedSignature: \(try other.signature(for: feed).base64EncodedString())\nlength: \(feed.count)\n-->\n".utf8)
        try wrong.write(to: root.appendingPathComponent("wrong-key.xml"))
        try Data(key.publicKey.rawRepresentation.base64EncodedString().utf8).write(to: root.appendingPathComponent("public-key.txt"))
        print("Prepared disposable signed feeds; private keys were not persisted.")
        return
    }
    guard arguments[1] == "probe", let bundle = Bundle(url: root),
          bundle.bundleIdentifier?.hasPrefix("dev.sebastiano.remozio.macos.experiments.sparkle.") == true else {
        throw NSError(domain: "Expected disposable probe bundle", code: 1)
    }
    guard Bundle.main.bundleIdentifier == bundle.bundleIdentifier,
          bundle.object(forInfoDictionaryKey: "SURequireSignedFeed") as? Bool == true,
          bundle.object(forInfoDictionaryKey: "SUVerifyUpdateBeforeExtraction") as? Bool == true,
          bundle.object(forInfoDictionaryKey: "SUSignedFeedFailureExpirationInterval") as? Int == 0 else {
        throw NSError(domain: "Unexpected fixture policy", code: 1)
    }
    // Pinned Sparkle fixture detail: prove zero expiry rejects even after a long failure history.
    UserDefaults.standard.set(Date(timeIntervalSince1970: 1), forKey: "SUInitialFailedFeedSigningValidationDate")
    let delegate = Probe()
    let driver = SPUStandardUserDriver(hostBundle: bundle, delegate: nil)
    let updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: driver, delegate: delegate)
    delegate.updater = updater
    try updater.start()
    updater.checkForUpdateInformation()
    let deadline = Date().addingTimeInterval(20)
    while !delegate.finished && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
    guard delegate.finished else { throw NSError(domain: "Probe timed out", code: 1) }
    let result: [String: Any] = ["found": delegate.found as Any? ?? NSNull(), "signatureValid": delegate.signatureValid,
                               "errorCode": delegate.errorCode as Any? ?? NSNull(),
                               "selectionChecks": delegate.selectionChecks, "frameworkError": delegate.frameworkError]
    print(String(decoding: try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
}

do { try MainActor.assumeIsolated { try run() } }
catch { FileHandle.standardError.write(Data("Sparkle probe failed: \(error)\n".utf8)); exit(1) }
