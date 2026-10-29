import os
import tempfile
import unittest
from pathlib import Path

from camoufox_trace_mcp.store import TraceStore

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "pilot.jsonl"


class TraceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "traces"
        self.root.mkdir()
        (self.root / "nested").mkdir()
        (self.root / "capture.jsonl").write_bytes(FIXTURE.read_bytes())
        (self.root / "nested" / "other.jsonl").write_bytes(FIXTURE.read_bytes())
        (self.directory / "outside.jsonl").write_bytes(FIXTURE.read_bytes())
        self.store = TraceStore(self.root)

    def test_regular_nested_files_and_paginated_listing(self):
        self.assertEqual(len(self.store.read("nested/other.jsonl").events), 3)
        listing = self.store.list(limit=1)
        self.assertEqual(listing["traces"], ["capture.jsonl"])
        self.assertEqual(listing["next_offset"], 1)
        self.assertEqual(self.store.list(offset=1)["traces"], ["nested/other.jsonl"])

    def test_absolute_parent_and_wrong_extension_are_refused(self):
        for name in (str(self.directory / "outside.jsonl"), "../outside.jsonl",
                     "nested/../../outside.jsonl", "capture.txt", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.store.read(name)

    def test_symlink_file_and_directory_escape_are_refused(self):
        (self.root / "linked.jsonl").symlink_to(self.directory / "outside.jsonl")
        (self.root / "linked_directory").symlink_to(self.directory, target_is_directory=True)
        (self.root / "internal.jsonl").symlink_to(self.root / "capture.jsonl")
        for name in ("linked.jsonl", "linked_directory/outside.jsonl", "internal.jsonl"):
            with self.subTest(name=name), self.assertRaises(OSError):
                self.store.read(name)
        self.assertEqual(self.store.list()["traces"], ["capture.jsonl", "nested/other.jsonl"])

    def test_special_files_are_rejected_without_blocking(self):
        os.mkfifo(self.root / "fifo.jsonl")
        with self.assertRaises(ValueError):
            self.store.read("fifo.jsonl")
        (self.root / "directory.jsonl").mkdir()
        with self.assertRaises(ValueError):
            self.store.read("directory.jsonl")

    def test_root_must_exist_and_be_a_directory(self):
        with self.assertRaises(FileNotFoundError):
            TraceStore(self.root / "absent")
        with self.assertRaises(ValueError):
            TraceStore(self.root / "capture.jsonl")


if __name__ == "__main__":
    unittest.main()
