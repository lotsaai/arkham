import importlib.util
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("amqp_witness", Path(__file__).with_name("amqp-witness.py"))
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
outcome = _mod.outcome

PORT = 5673


def flow(src_port: int, dst_port: int) -> str:
    return f"010.202.000.010.{src_port:05d}-010.202.000.100.{dst_port:05d}"


class OutcomeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.attempt = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, size: int) -> None:
        (self.attempt / name).write_bytes(b"x" * size)

    def test_good_pair_is_done(self) -> None:
        broker = flow(40000, PORT)
        client = flow(PORT, 40000)
        self.write(broker, 346)
        self.write(client, 658)
        self.write("report.xml", 20)
        kind, text = outcome(str(self.attempt), PORT)
        self.assertEqual(kind, "done")
        self.assertEqual(text, f"{broker}\n{client}\n")

    def test_missing_direction_is_empty(self) -> None:
        self.write(flow(40000, PORT), 346)
        kind, text = outcome(str(self.attempt), PORT)
        self.assertEqual(kind, "empty")
        self.assertEqual(text, "toBroker=346 toClient=0\n")

    def test_zero_size_direction_is_empty(self) -> None:
        self.write(flow(40000, PORT), 346)
        self.write(flow(PORT, 40000), 0)
        kind, text = outcome(str(self.attempt), PORT)
        self.assertEqual(kind, "empty")
        self.assertEqual(text, "toBroker=346 toClient=0\n")

    def test_two_files_for_one_direction_is_error(self) -> None:
        self.write(flow(40000, PORT), 10)
        self.write(flow(40001, PORT), 12)
        self.write(flow(PORT, 40000), 8)
        kind, text = outcome(str(self.attempt), PORT)
        self.assertEqual(kind, "error")
        self.assertIn("flow pairing failed", text)


if __name__ == "__main__":
    unittest.main()
