"""Safe Cowrie UML TTY frame parser tests (synthetic terminal tapes)."""
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from safe_tty_replay import FRAME, ReplayError, safe_replay


def frame(op, direction=0, body=b"", tty=42, sec=1795000000, usec=1):
    return FRAME.pack(op,tty,len(body),direction,sec,usec)+body


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"tty.bin"

    def write(self,*fragments):
        self.path.write_bytes(b"".join(fragments))

    def test_exact_stream_reconstruction_without_rendering(self):
        self.write(
          frame(1),
          frame(3,1,b"terminal prompt > "),
          frame(3,2,b"synthetic-input-secret-do-not-render"),
          frame(3,1,b"output"),
          frame(2),
        )
        result=safe_replay(self.path)
        self.assertTrue(result["validated"])
        self.assertFalse(result["rendered_to_terminal"])
        self.assertFalse(result["file_executed"])
        self.assertEqual(result["frames"],5)
        self.assertEqual(result["replayed_frames"],2)
        self.assertEqual(result["replayed_bytes"],len(b"terminal prompt > output"))
        self.assertEqual(result["replay_sha256"],
                         hashlib.sha256(b"terminal prompt > output").hexdigest())
        self.assertEqual(result["source_tty_sha256"],
                         hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_exec_interactive_always_included(self):
        self.write(frame(1),frame(3,3,b"safe simulated exec output"),frame(2))
        result=safe_replay(self.path)
        self.assertEqual(result["replayed_frames"],1)
        self.assertEqual(result["replayed_bytes"],len(b"safe simulated exec output"))

    def test_reject_truncated_frame(self):
        self.write(frame(1),b"\x01\x02\x03")
        with self.assertRaises(ReplayError):
            safe_replay(self.path)

    def test_reject_truncated_payload(self):
        self.write(frame(1),FRAME.pack(3,42,30,1,1795000000,5)+b"short")
        with self.assertRaises(ReplayError):
            safe_replay(self.path)

    def test_reject_unknown_op_and_invalid_direction(self):
        self.write(frame(18),frame(3,1,b"x"))
        with self.assertRaises(ReplayError):
            safe_replay(self.path)
        self.write(frame(1),frame(3,99,b"x"),frame(2))
        with self.assertRaises(ReplayError):
            safe_replay(self.path)

    def test_reject_negative_and_overlarge_frame(self):
        self.write(frame(1),FRAME.pack(3,42,-1,1,1795000000,0))
        with self.assertRaises(ReplayError):
            safe_replay(self.path)
        self.write(frame(1),FRAME.pack(3,42,1024*1024+1,1,1795000000,0))
        with self.assertRaises(ReplayError):
            safe_replay(self.path)

    def test_reject_microsecond_out_of_range(self):
        self.write(frame(1),frame(3,1,b"output",usec=1000000),frame(2))
        with self.assertRaises(ReplayError):
            safe_replay(self.path)

    def test_reject_no_output(self):
        self.write(frame(1),frame(2))
        with self.assertRaises(ReplayError):
            safe_replay(self.path)

    def test_reject_symlink_and_directory(self):
        linked=Path(self.temp.name)/"linked"
        self.write(frame(1),frame(3,1,b"output"),frame(2))
        linked.symlink_to(self.path)
        with self.assertRaises(ReplayError):
            safe_replay(linked)
        with self.assertRaises(ReplayError):
            safe_replay(Path(self.temp.name))


if __name__=="__main__":
    unittest.main()
