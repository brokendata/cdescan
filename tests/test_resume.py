import contextlib
import io
import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import unittest

import test_cdescan as baseline

host, scan, xml = baseline.host, baseline.scan, baseline.xml


class ResumeTests(unittest.TestCase):
    setUp = baseline.ConversionTests.setUp

    def invoke(self, argv, runner):
        with patch.object(scan.shutil, "which", return_value="/fixture/tool"), patch.object(
                scan.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "rustscan 2.4.1", "")), patch.object(
                scan, "run", side_effect=runner), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return scan.main(argv)

    def run_dir(self):
        return next((self.path / "results").iterdir())

    def nmap(self, command, directory):
        addresses = (directory / command[command.index("-iL") + 1]).read_text().splitlines()
        spec = command[command.index("-p") + 1]
        protocol = None
        selected = []
        for token in spec.split(","):
            if ":" in token:
                marker, token = token.split(":")
                protocol = {"T": "tcp", "U": "udp"}[marker]
            selected += [(protocol, port, "open") for port in range(int(token.split("-")[0]), int(token.split("-")[-1]) + 1)]
        xml(directory / command[command.index("-oX") + 1], [host(address, selected) for address in addresses])

    def imported_run(self, interrupt_second=False):
        imported = self.path / "import.xml"
        xml(imported, [host("192.0.2.1", [("tcp", 443, "open")]),
                       host("192.0.2.2", [("tcp", 22, "open")])])

        def runner(command, directory, manifest, save, label):
            if interrupt_second and "nmap-000002" in label:
                (directory / command[command.index("-oX") + 1]).write_text("<nmaprun>")
                raise KeyboardInterrupt()
            self.nmap(command, directory)

        result = self.invoke([str(self.targets), "--masscan-xml", str(imported), "--skip-html",
                              "--output-dir", str(self.path / "results")], runner)
        return result, self.run_dir()

    def test_masscan_resume_changes_rate_and_preserves_partial_xml_findings(self):
        partial = '<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/>' \
                  '<ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><host>'

        def interrupted(command, directory, manifest, save, label):
            self.assertEqual(command[0], "masscan")
            (directory / command[command.index("-oX") + 1]).write_text(partial)
            (directory / "paused.conf").write_text("rate = 10000\nresume-index = 123\nseed = 456\n")
            raise KeyboardInterrupt()

        result = self.invoke([str(self.targets), "--skip-html", "--tcp-ports", "22,443", "--udp-ports", "none",
                              "--output-dir", str(self.path / "results")], interrupted)
        self.assertEqual(result, 130)
        directory = self.run_dir()
        old_xml_hash = scan.sha256(directory / "masscan-part-0001.xml")
        checkpoint_hash = scan.sha256(directory / "paused.conf")
        calls = []

        def resumed(command, directory, manifest, save, label):
            calls.append(command)
            if command[0] == "masscan":
                self.assertLess(command.index("--resume"), command.index("--rate"))
                self.assertEqual(command[command.index("--rate") + 1], "1000")
                self.assertIn("--output-append=false", command)
                self.assertEqual(scan.sha256(directory / command[command.index("--resume") + 1]), checkpoint_hash)
                self.assertFalse((directory / "paused.conf").exists())
                xml(directory / command[command.index("-oX") + 1],
                    [host("192.0.2.1", [("tcp", 443, "open")]), host("192.0.2.2", [("tcp", 22, "open")])])
            else:
                self.nmap(command, directory)

        self.assertEqual(self.invoke(["--resume", str(directory), "--rate", "1000"], resumed), 0)
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["settings"]["rate"], 1000)
        self.assertEqual(manifest["resumes"][0]["overrides"], {"rate": 1000})
        self.assertEqual(manifest["discovered_endpoints"], 2)
        self.assertEqual(scan.sha256(directory / "masscan-part-0001.xml"), old_xml_hash)
        self.assertEqual(len(manifest["discovery"]["parts"]), 2)
        self.assertTrue(manifest["discovery"]["complete"])
        self.assertEqual(len(list(scan.elements(directory / "masscan.xml", "host"))), 2)
        self.assertEqual(len([command for command in calls if command[0] == "masscan"]), 1)

    def test_repeated_masscan_pause_preserves_all_attempts(self):
        rates = [10000, 1000, 500]
        seen = []

        def runner(command, directory, manifest, save, label):
            if command[0] == "masscan":
                seen.append(int(command[command.index("--rate") + 1]))
                xml(directory / command[command.index("-oX") + 1],
                    [host(f"192.0.2.{len(seen)}", [("tcp", 443, "open")])])
                if len(seen) < 3:
                    (directory / "paused.conf").write_text(f"resume-index = {len(seen)}\n")
                    raise KeyboardInterrupt()
            else:
                self.nmap(command, directory)

        self.assertEqual(self.invoke([str(self.targets), "--skip-html", "--output-dir", str(self.path / "results")], runner), 130)
        directory = self.run_dir()
        self.assertEqual(self.invoke(["--resume", str(directory), "--rate", "1000"], runner), 130)
        self.assertEqual(self.invoke(["--resume", str(directory), "--rate", "500"], runner), 0)
        self.assertEqual(seen, rates)
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["discovered_endpoints"], 3)
        self.assertEqual(len(list(directory.glob("masscan-checkpoint-*.conf"))), 2)

    def test_nmap_resume_skips_complete_job_and_keeps_interrupted_attempt(self):
        result, directory = self.imported_run(interrupt_second=True)
        self.assertEqual(result, 130)
        before = scan.sha256(directory / "nmap-000001-a001.xml")
        calls = []

        def runner(command, directory, manifest, save, label):
            calls.append(command)
            self.assertIn("nmap-000002-a002", label)
            self.assertIn("-T2", command)
            self.nmap(command, directory)

        self.assertEqual(self.invoke(["--resume", str(directory), "--timing", "2"], runner), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(scan.sha256(directory / "nmap-000001-a001.xml"), before)
        self.assertEqual((directory / "nmap-000002-a001.xml").read_text(), "<nmaprun>")
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["jobs"]["nmap-000002"]["attempts"], 2)
        self.assertEqual(manifest["nmap_hosts"]["total"], 2)
        self.assertEqual(len(list((directory / "history").glob("manifest-*.json"))), 1)

    def test_rustscan_resume_skips_complete_tcp_and_retries_udp_at_lower_concurrency(self):
        self.targets.write_text("192.0.2.1\n")
        calls = []
        def runner(command, directory, manifest, save, label, stdout_name=None):
            calls.append(command)
            if command[0] == "rustscan":
                (directory / stdout_name).write_text("192.0.2.1 -> [53]\n" if "--udp" in command else "192.0.2.1 -> [443]\n")
                if "--udp" in command and label.endswith("a001"):
                    raise KeyboardInterrupt()
                if "--udp" in command:
                    self.assertEqual(command[command.index("--batch-size") + 1], "64")
            else:
                self.nmap(command, directory)

        self.assertEqual(self.invoke([str(self.targets), "--scanner", "rustscan", "--tcp-ports", "443",
                                     "--udp-ports", "53", "--skip-html", "--output-dir", str(self.path / "results")], runner), 130)
        directory = self.run_dir()
        before = scan.sha256(next(directory.glob("rustscan-tcp-*.stdout")))
        self.assertEqual(self.invoke(["--resume", str(directory), "--rustscan-batch-size", "64"], runner), 0)
        self.assertEqual(len([cmd for cmd in calls if cmd[0] == "rustscan" and "--udp" not in cmd]), 1)
        self.assertEqual(scan.sha256(next(directory.glob("rustscan-tcp-*.stdout"))), before)
        self.assertEqual(len(list(directory.glob("rustscan-udp-*.stdout"))), 2)

    def test_resume_completed_run_launches_no_scanners(self):
        result, directory = self.imported_run()
        self.assertEqual(result, 0)
        calls = []
        self.assertEqual(self.invoke(["--resume", str(directory)], lambda *args: calls.append(args)), 0)
        self.assertEqual(calls, [])

    def test_resume_regenerates_real_html_without_repeating_nmap(self):
        imported = self.path / "import.xml"
        xml(imported, [host("192.0.2.1", [("tcp", 443, "open")])])
        real_run = scan.run
        calls = []

        def runner(command, directory, manifest, save, label):
            calls.append(command[0])
            if command[0] == "xsltproc":
                # invoke() patches version probes only; run() itself uses real Popen.
                real_run(command, directory, manifest, save, label)
            else:
                self.nmap(command, directory)

        self.assertEqual(self.invoke([str(self.targets), "--masscan-xml", str(imported),
                                     "--output-dir", str(self.path / "results")], runner), 0)
        directory = self.run_dir()
        self.assertEqual(self.invoke(["--resume", str(directory)], runner), 0)
        self.assertEqual(calls, ["nmap", "xsltproc", "xsltproc"])
        self.assertIn("192.0.2.1", (directory / "nmap-bootstrap.html").read_text())
        self.assertEqual(len(list(directory.glob("bootstrap-report-*.log"))), 2)

    def test_resume_checks_scope_and_completed_evidence_hashes(self):
        for filename in ("targets.txt", "nmap-000001-a001.xml"):
            with self.subTest(filename=filename):
                result, directory = self.imported_run()
                original = (directory / filename).read_bytes()
                before = (directory / "manifest.json").read_bytes()
                (directory / filename).write_text("changed")
                with self.assertRaises(SystemExit) as error:
                    self.invoke(["--resume", str(directory)], lambda *args: self.fail("scanner launched"))
                self.assertEqual(error.exception.code, 2)
                self.assertEqual((directory / "manifest.json").read_bytes(), before)
                (directory / filename).write_bytes(original)

    def test_resume_rejects_scope_and_backend_changes(self):
        result, directory = self.imported_run()
        for options in [["--scanner", "rustscan"], ["--tcp-ports", "80"], ["--batch-size", "1"],
                        [str(self.targets)], ["--interface", "eth1"]]:
            with self.subTest(options=options), self.assertRaises(SystemExit):
                self.invoke(["--resume", str(directory)] + options, lambda *args: self.fail("scanner launched"))

    def test_resume_dry_run_is_read_only(self):
        result, directory = self.imported_run()
        before = (directory / "manifest.json").read_bytes()
        self.assertEqual(self.invoke(["--resume", str(directory), "--rate", "1000", "--dry-run"],
                                     lambda *args: self.fail("scanner launched")), 0)
        self.assertEqual((directory / "manifest.json").read_bytes(), before)
        self.assertFalse((directory / "history").exists())

    def test_resume_lock_prevents_concurrent_writes(self):
        import fcntl
        result, directory = self.imported_run()
        with (directory / ".cdescan.lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(SystemExit):
                self.invoke(["--resume", str(directory)], lambda *args: self.fail("scanner launched"))

    def test_resume_rejects_legacy_runs(self):
        result, directory = self.imported_run()
        manifest = json.loads((directory / "manifest.json").read_text())
        manifest.pop("checkpoint_schema")
        (directory / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(SystemExit):
            self.invoke(["--resume", str(directory)], lambda *args: self.fail("scanner launched"))

    def test_missing_masscan_checkpoint_fails_without_restarting_discovery(self):
        def failed(command, directory, manifest, save, label):
            (directory / command[command.index("-oX") + 1]).write_text("<nmaprun>")
            raise RuntimeError("scanner died without checkpoint")
        self.assertEqual(self.invoke([str(self.targets), "--skip-html", "--output-dir", str(self.path / "results")], failed), 1)
        directory = self.run_dir()
        self.assertEqual(self.invoke(["--resume", str(directory), "--rate", "1000"],
                                     lambda *args: self.fail("discovery restarted")), 1)

    def test_ctrl_c_forwards_sigint_and_waits_for_checkpoint_flush(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.wait.side_effect = [KeyboardInterrupt(), 0]
        process.returncode = 0
        manifest = {"commands": [], "settings": {"wait": 10}}
        with patch.object(scan.subprocess, "Popen", return_value=process), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                scan.run(["masscan"], self.path, manifest, lambda: None, "stop")
        process.send_signal.assert_called_once_with(signal.SIGINT)
        process.kill.assert_not_called()
        self.assertTrue(manifest["commands"][0]["interrupted"])
        self.assertEqual(process.wait.call_args.kwargs, {"timeout": 30})

    def test_graceful_stop_flushes_a_real_child_checkpoint(self):
        script = self.path / "checkpoint_child.py"
        script.write_text('''import signal, time
from pathlib import Path
def stop(*args):
    Path('paused.conf').write_text('resume-index = 123\\n')
    raise SystemExit(0)
signal.signal(signal.SIGINT, stop)
Path('ready').touch()
while True:
    time.sleep(0.01)
''')
        real_popen = subprocess.Popen

        class InterruptOnce(real_popen):
            first_wait = True

            def wait(child, *args, **kwargs):
                if child.first_wait:
                    child.first_wait = False
                    deadline = time.monotonic() + 5
                    while not (self.path / "ready").exists():
                        if time.monotonic() > deadline:
                            child.kill()
                            raise RuntimeError("child did not start")
                        time.sleep(0.01)
                    raise KeyboardInterrupt()
                return super().wait(*args, **kwargs)

        manifest = {"commands": [], "settings": {"wait": 10}}
        with patch.object(scan.subprocess, "Popen", InterruptOnce), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                scan.run([sys.executable, str(script)], self.path, manifest, lambda: None, "child")
        self.assertEqual((self.path / "paused.conf").read_text(), "resume-index = 123\n")
        self.assertEqual(manifest["commands"][0]["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
