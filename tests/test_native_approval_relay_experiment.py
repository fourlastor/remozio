import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-native-approval-relay-experiment.py"
SPEC = importlib.util.spec_from_file_location("native_relay_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


class ExtensionUpgradeTests(unittest.TestCase):
    def test_rejected_extension_offer_cannot_produce_passing_evidence(self):
        class RejectedSocket:
            def __init__(self):
                self.response = io.BytesIO(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                self.request = b""

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def sendall(self, data):
                self.request += data

            def recv(self, count):
                return self.response.read(count)

        sock = RejectedSocket()
        with patch.object(EXPERIMENT, "Probe") as probe:
            probe.return_value.connect.return_value = sock
            with self.assertRaisesRegex(RuntimeError, "Valid upgrade refused"):
                EXPERIMENT.framing(Path("/unused"), "extensionsNotNegotiated")
            self.assertIn(b"Sec-WebSocket-Extensions: permessage-deflate\r\n", sock.request)
            probe.return_value.close.assert_called_once()

    def test_probe_and_upgrade_finish_before_the_accept_wait_starts(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        response = io.BytesIO(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        sock.recv.side_effect = response.read
        listener = MagicMock()
        listener.getsockname.return_value = ("127.0.0.1", 12345)
        worker = MagicMock()
        probe = MagicMock()
        probe.connect.return_value = sock

        def ready_probe(*_args):
            worker.start.assert_not_called()
            return probe

        def ready_upgrade(*args, **kwargs):
            worker.start.assert_not_called()
            return upgrade(*args, **kwargs)

        upgrade = EXPERIMENT.upgrade
        with patch.object(EXPERIMENT.socket, "socket", return_value=listener), \
             patch.object(EXPERIMENT.threading, "Thread", return_value=worker), \
             patch.object(EXPERIMENT, "Probe", side_effect=ready_probe), \
             patch.object(EXPERIMENT, "upgrade", side_effect=ready_upgrade):
            with self.assertRaisesRegex(RuntimeError, "Valid upgrade refused"):
                EXPERIMENT.framing(Path("/unused"), "extensionsNotNegotiated")
        worker.start.assert_called_once()
        worker.join.assert_called_once_with(timeout=7)
        listener.close.assert_called_once()
        probe.close.assert_called_once()
