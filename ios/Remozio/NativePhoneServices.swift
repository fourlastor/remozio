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
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
        guard var top = scene?.keyWindow?.rootViewController else { return deliver(nil) }
        while let presented = top.presentedViewController { top = presented }
        top.present(QRScannerController(onFinish: deliver), animated: true)
    }
}

/// Full-screen camera view that returns the first QR code it reads, or nil on Cancel.
private final class QRScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private var onFinish: ((String?) -> Void)?

    init(onFinish: @escaping (String?) -> Void) {
        self.onFinish = onFinish
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .fullScreen
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let camera = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: camera),
              session.canAddInput(input) else { return finish(nil) }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return finish(nil) }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.layer.bounds
        view.layer.addSublayer(preview)

        let cancel = UIButton(type: .system, primaryAction: UIAction(title: "Cancel") { [weak self] _ in self?.finish(nil) })
        cancel.translatesAutoresizingMaskIntoConstraints = false
        cancel.tintColor = .white
        view.addSubview(cancel)
        NSLayoutConstraint.activate([
            cancel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
            cancel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
        ])
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let text = objects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first else { return }
        finish(text)
    }

    private func finish(_ text: String?) {
        guard let onFinish else { return }
        self.onFinish = nil
        session.stopRunning()
        dismiss(animated: true) { onFinish(text) }
    }
}
