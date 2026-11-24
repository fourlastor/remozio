#if DEBUG
import Network
import RemozioUI
import SwiftUI
import UIKit

struct PairingPreviewEntry: View {
    let endpoint: NWEndpoint
    @State private var showingPreview = false

    var body: some View {
        Button("Pairing preview") { showingPreview = true }
            .buttonStyle(.borderedProminent)
            .padding()
            .sheet(isPresented: $showingPreview) {
                PairingPreviewScreen(endpoint: endpoint)
            }
    }

    static func endpoint(_ address: String?) -> NWEndpoint? {
        let prefix = "127.0.0.1:"
        guard let address, address.hasPrefix(prefix),
              let raw = UInt16(address.dropFirst(prefix.count)), raw != 0,
              let port = NWEndpoint.Port(rawValue: raw) else { return nil }
        return .hostPort(host: .ipv4(.loopback), port: port)
    }
}

private struct PairingPreviewScreen: UIViewControllerRepresentable {
    let endpoint: NWEndpoint

    func makeUIViewController(context: Context) -> PairingPreviewController {
        PairingPreviewController(endpoint: endpoint)
    }

    func updateUIViewController(_ controller: PairingPreviewController, context: Context) {}

    static func dismantleUIViewController(_ controller: PairingPreviewController, coordinator: ()) {
        controller.leave()
    }
}

final class PairingPreviewInput: UITextField {
    init() {
        super.init(frame: .zero)
        borderStyle = .roundedRect
        placeholder = "Pairing invitation"
        isSecureTextEntry = true
        textContentType = nil
        autocorrectionType = .no
        autocapitalizationType = .none
        spellCheckingType = .no
        inlinePredictionType = .no
        smartInsertDeleteType = .no
        smartDashesType = .no
        smartQuotesType = .no
        accessibilityLabel = "Pairing invitation"
    }

    required init?(coder: NSCoder) { return nil }

    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool { false }
}

final class PairingPreviewController: UIViewController, UITextFieldDelegate {
    private let endpoint: NWEndpoint
    let input = PairingPreviewInput()
    private let message = UILabel()
    private let checkButton = UIButton(type: .system)
    private let services = NativePhoneServices()
    private weak var privacyWindow: UIWindow?
    private var cover: UIView?
    private var invitation: IosPairingPreviewInvitation?
    private var attempt: IosPairingPreviewAttempt?
    private var generation = UUID()
    private var left = false

    init(endpoint: NWEndpoint) {
        self.endpoint = endpoint
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { return nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        pasteConfiguration = UIPasteConfiguration(forAccepting: NSString.self)
        input.delegate = self
        input.returnKeyType = .done
        message.text = "Import a v2 pairing invitation."
        message.font = .preferredFont(forTextStyle: .body)
        message.adjustsFontForContentSizeCategory = true
        message.numberOfLines = 0
        message.accessibilityTraits.insert(.updatesFrequently)
        checkButton.setTitle("Check invitation", for: .normal)
        checkButton.isEnabled = false
        checkButton.addTarget(self, action: #selector(checkInvitation), for: .touchUpInside)

        let paste = UIPasteControl(configuration: .init())
        paste.target = self
        let scan = UIButton(type: .system, primaryAction: UIAction(title: "Scan QR") { [weak self] _ in self?.scan() })
        let importText = UIButton(type: .system, primaryAction: UIAction(title: "Import text") { [weak self] _ in self?.submitText() })
        let close = UIButton(type: .system, primaryAction: UIAction(title: "Close") { [weak self] _ in self?.dismissPreview() })
        let title = UILabel()
        title.text = "Pairing preview"
        title.font = .preferredFont(forTextStyle: .headline)
        title.adjustsFontForContentSizeCategory = true
        title.accessibilityTraits.insert(.header)
        let stack = UIStackView(arrangedSubviews: [title, input, importText, paste, scan, checkButton, message, close])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        let scroll = UIScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.keyboardDismissMode = .interactive
        scroll.addSubview(stack)
        view.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.keyboardLayoutGuide.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -24),
            stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -24),
            stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -48),
        ])

        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(protectScene(_:)), name: UIScene.willDeactivateNotification, object: nil)
        center.addObserver(self, selector: #selector(clearBackgroundScene(_:)), name: UIScene.didEnterBackgroundNotification, object: nil)
        center.addObserver(self, selector: #selector(revealScene(_:)), name: UIScene.didActivateNotification, object: nil)
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        privacyWindow = view.window
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        if isBeingDismissed || navigationController?.isBeingDismissed == true {
            leave()
        }
    }

    override func paste(itemProviders: [NSItemProvider]) {
        guard itemProviders.count == 1, let provider = itemProviders.first,
              provider.canLoadObject(ofClass: NSString.self) else { return }
        let count = UIPasteboard.general.changeCount
        let version = generation
        _ = provider.loadObject(ofClass: NSString.self) { [weak self] object, _ in
            DispatchQueue.main.async {
                guard let self, let text = object as? String, self.acceptsInput(version) else { return }
                if self.importInvitation(text) {
                    Self.clearPasteboard(ifUnchanged: count, current: { UIPasteboard.general.changeCount }) {
                        UIPasteboard.general.items = []
                    }
                }
            }
        }
    }

    static func clearPasteboard(ifUnchanged count: Int, current: () -> Int, clear: () -> Void) {
        if current() == count { clear() }
    }

    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        (textField.text?.utf16.count ?? 0) - range.length + string.utf16.count <= 1_100
    }

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        submitText()
        return false
    }

    private func submitText() {
        _ = importInvitation(input.text ?? "")
        input.resignFirstResponder()
    }

    private func scan() {
        let version = generation
        services.scanQrCode { [weak self] text in
            guard let self, let text, self.acceptsInput(version) else { return }
            _ = self.importInvitation(text)
        }
    }

    private func acceptsInput(_ version: UUID) -> Bool {
        !left && generation == version && privacyWindow?.windowScene?.activationState == .foregroundActive
    }

    @discardableResult
    func importInvitation(_ text: String) -> Bool {
        reset()
        guard let parsed = IosPairingV2Preview.shared.parseInvitation(text: text) else {
            message.text = "Enter a valid v2 pairing invitation."
            return false
        }
        invitation = parsed
        message.text = "Ready to check \(parsed.label)."
        checkButton.isEnabled = true
        return true
    }

    @objc private func checkInvitation() {
        guard let invitation else { return }
        self.invitation = nil
        checkButton.isEnabled = false
        input.text = nil
        message.text = "Checking the invitation…"
        let version = generation
        let keys = NativePairingKeys(endpoint: endpoint)
        attempt = invitation.start(keys: keys, result: PairingPreviewCompletion { [weak self] code in
            guard let self, self.acceptsInput(version) else { return }
            self.attempt = nil
            self.message.text = code.map { "Invitation verified. Comparison code: \($0)" }
                ?? "The invitation could not be verified."
        })
    }

    @objc private func protectScene(_ notification: Notification) {
        guard cover == nil, let window = mentionedWindow(notification) else { return }
        let overlay = UIView(frame: window.bounds)
        overlay.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        overlay.backgroundColor = .systemBackground
        overlay.accessibilityViewIsModal = true
        window.addSubview(overlay)
        cover = overlay
    }

    @objc private func clearBackgroundScene(_ notification: Notification) {
        guard mentionedWindow(notification) != nil else { return }
        protectScene(notification)
        reset()
        message.text = "Import a v2 pairing invitation."
        presentedViewController?.dismiss(animated: false)
    }

    @objc private func revealScene(_ notification: Notification) {
        guard mentionedWindow(notification) != nil else { return }
        cover?.removeFromSuperview()
        cover = nil
    }

    private func mentionedWindow(_ notification: Notification) -> UIWindow? {
        guard let window = privacyWindow, let scene = notification.object as? UIWindowScene,
              scene === window.windowScene else { return nil }
        return window
    }

    private func dismissPreview() {
        leave()
        dismiss(animated: true)
    }

    func leave() {
        left = true
        reset()
        cover?.removeFromSuperview()
        cover = nil
    }

    private func reset() {
        generation = UUID()
        input.text = nil
        invitation = nil
        attempt?.cancel()
        attempt = nil
        checkButton.isEnabled = false
    }

    deinit {
        attempt?.cancel()
        cover?.removeFromSuperview()
    }
}

private final class PairingPreviewCompletion: NSObject, IosPairingPreviewResult {
    private let completion: (String?) -> Void

    init(_ completion: @escaping (String?) -> Void) { self.completion = completion }

    func finished(code: String?) {
        DispatchQueue.main.async { [self] in completion(code) }
    }
}
#endif
