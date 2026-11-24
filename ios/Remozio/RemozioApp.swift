import RemozioUI
import SwiftUI

@main
struct RemozioApp: App {
    var body: some Scene {
        WindowGroup {
            // Compose draws under the status bar and home indicator and pads its own content by those insets.
            SharedRoot().ignoresSafeArea()
                #if DEBUG
                .overlay(alignment: .topTrailing) {
                    if let endpoint = PairingPreviewEntry.endpoint(ProcessInfo.processInfo.environment["REMOZIO_PAIRING_PREVIEW_ENDPOINT"]) {
                        PairingPreviewEntry(endpoint: endpoint)
                    }
                }
                #endif
        }
    }
}

/// Hosts the Compose Multiplatform screens from the RemozioUI framework.
private struct SharedRoot: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UIViewController {
        MainViewControllerKt.MainViewController(services: NativePhoneServices())
    }

    func updateUIViewController(_ controller: UIViewController, context: Context) {}
}
