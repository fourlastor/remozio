import ServiceManagement
import SwiftUI

@main
struct PackagingApp: App {
    var body: some Scene {
        WindowGroup("Remozio packaging experiment") {
            VStack(alignment: .leading, spacing: 16) {
                Text("Remozio packaging experiment").font(.title)
                Text("This bundle tests packaging only. It cannot approve requests or execute commands.")
                LabeledContent("Session probe", value: status(SMAppService.agent(plistName: "dev.sebastiano.remozio.macos.experiments.session.plist")))
                LabeledContent("Authority probe", value: status(SMAppService.daemon(plistName: "dev.sebastiano.remozio.macos.experiments.authority.plist")))
                Text("Services are not registered by this app. Installation and update tests require a signed release and an interactive test session.")
                    .foregroundStyle(.secondary)
            }
            .padding(24)
            .frame(width: 540)
        }
        .windowResizability(.contentSize)
    }

    private func status(_ service: SMAppService) -> String {
        switch service.status {
        case .notRegistered: "Not registered"
        case .enabled: "Registered; execution not verified"
        case .requiresApproval: "Requires system approval"
        case .notFound: "Service not found"
        @unknown default: "Unknown"
        }
    }
}
