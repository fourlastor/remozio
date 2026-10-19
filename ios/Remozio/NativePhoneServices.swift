import AVFoundation
import RemozioUI
import UIKit

/// iOS implementations of the services that the shared screens call.
final class NativePhoneServices: NSObject, PhoneServices {
    func pasteText() -> String? {
        UIPasteboard.general.string
    }

    func scanQrCode(onResult: @escaping (String?) -> Void) {
        let deliver: (String?) -> Void = { text in DispatchQueue.main.async { onResult(text) } }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            DispatchQueue.main.async { Self.presentScanner(deliver) }
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                if granted {
                    DispatchQueue.main.async { Self.presentScanner(deliver) }
                } else {
                    deliver(nil)
                }
            }
        default:
            deliver(nil)
        }
    }

    @MainActor
    private static func presentScanner(_ deliver: @escaping (String?) -> Void) {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let scene = scenes.first { $0.activationState == .foregroundActive } ?? scenes.first
        let window = scene?.keyWindow ?? scene?.windows.first
        guard var top = window?.rootViewController else { return deliver(nil) }
        while let presented = top.presentedViewController { top = presented }
        top.present(QRScannerController(onFinish: deliver), animated: true)
    }
}

/// Full-screen camera view that returns the first QR code it reads, or nil on Cancel.
private final class QRScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    // startRunning and stopRunning block, so they run on this queue and never on the main thread.
    private let sessionQueue = DispatchQueue(label: "dev.remozio.scanner")
    private let preview: AVCaptureVideoPreviewLayer
    private var configured = false
    private var onFinish: ((String?) -> Void)?

    init(onFinish: @escaping (String?) -> Void) {
        self.onFinish = onFinish
        preview = AVCaptureVideoPreviewLayer(session: session)
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .fullScreen
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)

        let cancel = UIButton(type: .system, primaryAction: UIAction(title: "Cancel") { [weak self] _ in self?.finish(nil) })
        cancel.translatesAutoresizingMaskIntoConstraints = false
        cancel.tintColor = .white
        view.addSubview(cancel)
        NSLayoutConstraint.activate([
            cancel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
            cancel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
        ])

        guard let camera = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: camera),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        configured = true
        let session = session
        sessionQueue.async { session.startRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview.frame = view.layer.bounds
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        // A failed camera setup can only be dismissed once the presentation has finished.
        if !configured { finish(nil) }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let text = objects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first else { return }
        finish(text)
    }

    private func finish(_ text: String?) {
        guard let onFinish else { return }
        self.onFinish = nil
        let session = session
        sessionQueue.async {
            session.stopRunning()
            DispatchQueue.main.async { self.dismiss(animated: true) { onFinish(text) } }
        }
    }
}
