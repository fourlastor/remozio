import RemozioUI
import SwiftUI

@main
struct RemozioApp: App {
    var body: some Scene {
        WindowGroup {
            SharedRoot().ignoresSafeArea(.keyboard)
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
