import io
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
RECEIVER = ROOT / "scripts" / "receive-orchestrator-artifacts.py"
RUNNER = ROOT / "scripts" / "test-orchestrator-offline-container.sh"
ARTIFACTS = ("mipsorcu-orchestrator", "mipsorcu_orchestrator", "postgres_integration", "engine_postgres")
LIMIT = 128 * 1024 * 1024
RUNNER_SOURCE = RUNNER.read_text()
RECEIVE_FUNCTION = RUNNER_SOURCE[RUNNER_SOURCE.index("receive_artifacts() {"):]
RECEIVE_FUNCTION = RECEIVE_FUNCTION[:RECEIVE_FUNCTION.index("\n}") + 2]


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as writer:
        for entry in entries:
            name, kind, data = entry[:3]
            mode = entry[3] if len(entry) == 4 else 0o500
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.type = kind
            info.size = len(data)
            writer.addfile(info, io.BytesIO(data) if data else None)
    return output.getvalue()


def oversized_header(name):
    info = tarfile.TarInfo(name)
    info.mode = 0o500
    info.size = LIMIT + 1
    return info.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)


class ArtifactReceiverTest(unittest.TestCase):
    def run_receiver(self, mode, data, *, existing=()):
        with tempfile.TemporaryDirectory(prefix="orchestrator-artifacts-") as temp:
            output_dir = pathlib.Path(temp) / "artifacts"
            output_dir.mkdir(mode=0o700)
            output_dir.chmod(0o700)
            for name, value in existing:
                (output_dir / name).write_bytes(value)
                (output_dir / name).chmod(0o600)
            result = subprocess.run(
                [sys.executable, str(RECEIVER), mode, str(output_dir)],
                input=data,
                capture_output=True,
                check=False,
            )
            contents = {path.name: path.read_bytes() for path in output_dir.iterdir() if path.is_file()}
            return result, contents

    def run_receive_function(self, data, *, fail_kill=False):
        with tempfile.TemporaryDirectory(prefix="orchestrator-artifacts-") as temp:
            output_dir = pathlib.Path(temp) / "artifacts"
            output_dir.mkdir(mode=0o700)
            output_dir.chmod(0o700)
            killed = pathlib.Path(temp) / "killed-container"
            shell = """docker() {
    if [ "$1" = kill ]; then
        printf '%s' "$2" > "$KILLED_CONTAINER"
        [ "$KILL_FAILURE" != 1 ] || return 71
        return 0
    fi
    return 90
}
""" + RECEIVE_FUNCTION + "\nreceive_artifacts \"$RECEIVER\" demo \"$OUTPUT_DIR\" builder-fixture"
            environment = {
                **os.environ,
                "KILLED_CONTAINER": str(killed),
                "KILL_FAILURE": "1" if fail_kill else "0",
                "OUTPUT_DIR": str(output_dir),
                "RECEIVER": str(RECEIVER),
            }
            result = subprocess.run(
                ["bash", "-c", shell], input=data, capture_output=True, check=False, env=environment
            )
            files = {path.name: path.read_bytes() for path in output_dir.iterdir() if path.is_file()}
            return result, files, killed.read_text() if killed.exists() else None

    def test_runner_transfer_keeps_artifact_without_stopping_builder(self):
        result, files, killed = self.run_receive_function(
            archive([(ARTIFACTS[0], tarfile.REGTYPE, b"binary")])
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(files, {ARTIFACTS[0]: b"binary"})
        self.assertIsNone(killed)

    def test_runner_transfer_stops_builder_when_archive_is_invalid(self):
        result, files, killed = self.run_receive_function(b"invalid archive")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files, {})
        self.assertEqual(killed, "builder-fixture")

    def test_failed_builder_stop_does_not_hide_invalid_archive(self):
        result, files, killed = self.run_receive_function(b"invalid archive", fail_kill=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files, {})
        self.assertEqual(killed, "builder-fixture")

    def test_demo_receives_only_the_executable_artifact(self):
        result, contents = self.run_receiver("demo", archive([(ARTIFACTS[0], tarfile.REGTYPE, b"binary")]))

        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(contents, {"mipsorcu-orchestrator": b"binary"})

    def test_postgres_mode_receives_the_exact_three_executables(self):
        entries = [(name, tarfile.REGTYPE, name.encode()) for name in ARTIFACTS[1:]]
        with tempfile.TemporaryDirectory(prefix="orchestrator-artifacts-") as temp:
            output_dir = pathlib.Path(temp) / "artifacts"
            output_dir.mkdir(mode=0o700)
            output_dir.chmod(0o700)
            result = subprocess.run(
                [sys.executable, str(RECEIVER), "postgres-tests", str(output_dir)],
                input=archive(entries),
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(sorted(path.name for path in output_dir.iterdir()), sorted(ARTIFACTS[1:]))
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o500 for path in output_dir.iterdir()))
            self.assertEqual({path.name: path.read_bytes() for path in output_dir.iterdir()},
                             {name: name.encode() for name in ARTIFACTS[1:]})

    def test_rejects_an_unlisted_or_traversal_name(self):
        for name in ("unexpected", "../mipsorcu-orchestrator"):
            with self.subTest(name=name):
                result, _ = self.run_receiver("demo", archive([(name, tarfile.REGTYPE, b"x")]))
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_links_and_special_entries(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE):
            with self.subTest(kind=kind):
                result, _ = self.run_receiver("demo", archive([(ARTIFACTS[0], kind, b"")]))
                self.assertNotEqual(result.returncode, 0)

    def test_rejects_duplicates_and_missing_artifacts(self):
        duplicate = archive([(ARTIFACTS[0], tarfile.REGTYPE, b"a"), (ARTIFACTS[0], tarfile.REGTYPE, b"b")])
        missing = archive([])
        self.assertNotEqual(self.run_receiver("demo", duplicate)[0].returncode, 0)
        self.assertNotEqual(self.run_receiver("postgres-tests", archive([(ARTIFACTS[1], tarfile.REGTYPE, b"a")]))[0].returncode, 0)
        self.assertNotEqual(self.run_receiver("demo", missing)[0].returncode, 0)

    def test_rejects_a_corrupt_checksum_and_truncated_payload(self):
        valid = bytearray(archive([(ARTIFACTS[0], tarfile.REGTYPE, b"payload")]))
        valid[0] ^= 1
        self.assertNotEqual(self.run_receiver("demo", bytes(valid))[0].returncode, 0)

        info = tarfile.TarInfo(ARTIFACTS[0])
        info.mode = 0o500
        info.size = 8
        truncated = info.tobuf(format=tarfile.USTAR_FORMAT) + b"x"
        self.assertNotEqual(self.run_receiver("demo", truncated)[0].returncode, 0)

    def test_rejects_forged_oversize_and_unexpected_permissions(self):
        self.assertNotEqual(self.run_receiver("demo", oversized_header(ARTIFACTS[0]))[0].returncode, 0)
        info = tarfile.TarInfo(ARTIFACTS[0])
        info.mode = 0o755
        info.size = 1
        unsafe_mode = info.tobuf(format=tarfile.USTAR_FORMAT) + b"x" + bytes(511 + 1024)
        self.assertNotEqual(self.run_receiver("demo", unsafe_mode)[0].returncode, 0)
        self.assertNotEqual(self.run_receiver("demo", archive([(ARTIFACTS[0], tarfile.REGTYPE, b"")]))[0].returncode, 0)

    def test_rejects_nonzero_file_and_archive_padding(self):
        valid = bytearray(archive([(ARTIFACTS[0], tarfile.REGTYPE, b"x")]))
        valid[513] = 1
        self.assertNotEqual(self.run_receiver("demo", bytes(valid))[0].returncode, 0)

        valid = bytearray(archive([(ARTIFACTS[0], tarfile.REGTYPE, b"x")]))
        valid[-1] = 1
        self.assertNotEqual(self.run_receiver("demo", bytes(valid))[0].returncode, 0)

    def test_rejects_oversized_trailer_and_preexisting_output(self):
        valid = archive([(ARTIFACTS[0], tarfile.REGTYPE, b"x")])
        self.assertNotEqual(self.run_receiver("demo", valid + bytes(1024 * 1024 + 1))[0].returncode, 0)
        self.assertNotEqual(self.run_receiver("demo", valid, existing=((ARTIFACTS[0], b"old"),))[0].returncode, 0)


if __name__ == "__main__":
    unittest.main()
