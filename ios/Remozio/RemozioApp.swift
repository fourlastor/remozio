import RemozioUI
import SwiftUI

@main
struct RemozioApp: App {
    var body: some Scene {
        WindowGroup {
            // Compose draws under the status bar and home indicator and pads its own content by those insets.
            SharedRoot().ignoresSafeArea()
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
