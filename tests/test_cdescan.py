import csv
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cdescan as scan


def host(ip, ports):
    element = ET.Element("host")
    ET.SubElement(element, "status", state="up", reason="user-set")
    ET.SubElement(element, "address", addr=ip, addrtype="ipv4")
    container = ET.SubElement(element, "ports")
    for protocol, number, state in ports:
        port = ET.SubElement(container, "port", protocol=protocol, portid=str(number))
        ET.SubElement(port, "state", state=state, reason="syn-ack")
    return element


def xml(path, hosts, complete=True):
    root = ET.Element("nmaprun", scanner="nmap")
    root.extend(hosts)
    if complete:
        ET.SubElement(ET.SubElement(root, "runstats"), "finished", exit="success")
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


class ConversionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.targets = self.path / "targets.txt"
        self.targets.write_text("# PCI scope\n192.0.2.0/24\n")
        self.normal = self.path / "normal.txt"
        scan.snapshot_targets(self.targets, self.normal)
        self.scope = scan.Scope(self.normal)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)

    def load(self, hosts):
        path = self.path / "masscan.xml"
        xml(path, hosts)
        scan.load_discovery(path, self.db, self.scope)
        return path

    def test_scope_and_ports(self):
        self.assertIn("192.0.2.255", self.scope)
        self.assertNotIn("192.0.3.0", self.scope)
        self.assertEqual(scan.ports("443,80-82,81,0,65535"), "0,80-82,443,65535")
        self.assertEqual(scan.ports("none"), "")
        for value in ("-1", "65536", "80-1", "1-2-3", ""):
            with self.assertRaises(Exception):
                scan.ports(value)
        self.targets.write_text("::1\n")
        with self.assertRaises(ValueError):
            scan.snapshot_targets(self.targets, self.normal)

    def test_dedup_and_host_specific_protocols(self):
        self.load([host("192.0.2.1", [("tcp", 443, "open")]),
                   host("192.0.2.1", [("tcp", 443, "open"), ("udp", 53, "open")]),
                   host("192.0.2.2", [("tcp", 22, "open"), ("udp", 161, "closed")]),
                   host("192.0.2.3", [("tcp", 22, "open")])])
        groups = list(scan.plans(self.db, 128))
        self.assertEqual(groups, [(("443", "53"), ["192.0.2.1"]),
                                  (("22", ""), ["192.0.2.2", "192.0.2.3"])])
        self.assertTrue(all(len(addresses) <= 1 for _, addresses in scan.plans(self.db, 1)))

    def test_rejects_out_of_scope_import(self):
        with self.assertRaises(ValueError):
            self.load([host("198.51.100.1", [("tcp", 443, "open")])])

    def test_rejects_excluded_import(self):
        excluded = self.path / "excluded.txt"
        excluded.write_text("192.0.2.1/32\n")
        path = self.path / "masscan.xml"
        xml(path, [host("192.0.2.1", [("tcp", 443, "open")])])
        with self.assertRaises(ValueError):
            scan.load_discovery(path, self.db, self.scope, scan.Scope(excluded))

    def test_truncated_xml_is_an_error(self):
        path = self.path / "masscan.xml"
        path.write_text('<nmaprun><host><address addr="192.0.2.1"/>')
        with self.assertRaises(ET.ParseError):
            scan.load_discovery(path, self.db, self.scope)

    def test_ambiguous_and_omitted_states_are_preserved(self):
        self.load([host("192.0.2.1", [("tcp", 443, "open"), ("udp", 53, "open")])])
        report = self.path / "nmap.xml"
        xml(report, [host("192.0.2.1", [("udp", 53, "open|filtered")])])
        scan.export_csv(self.db, report, self.path)
        with (self.path / "endpoint-evidence.csv").open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual([row["nmap_state"] for row in rows],
                         ["not_individually_reported", "open|filtered"])
        self.assertTrue(all(row["masscan_state"] == "open" for row in rows))

    def test_merging_requires_completed_jobs(self):
        source = self.path / "job.xml"
        xml(source, [host("192.0.2.1", [("tcp", 443, "open")])], complete=False)
        with self.assertRaises(RuntimeError):
            scan.merge_reports([source], self.path / "merged.xml", time.time())

    def test_empty_results_still_generate_reports(self):
        output = self.path / "nmap.xml"
        counts = scan.merge_reports([], output, time.time())
        self.assertEqual(counts["total"], 0)
        self.assertEqual(ET.parse(output).find("runstats/finished").get("exit"), "success")
        subprocess.run(["xsltproc", "--nonet", "-o", str(self.path / "empty.html"),
                        str(ROOT / "nmap-bootstrap.xsl"), str(output)], check=True,
                       capture_output=True)
        self.assertIn("Nmap", (self.path / "empty.html").read_text())

    def test_full_pipeline_with_simulated_scanners_and_real_xslt(self):
        imported = self.path / "import.xml"
        xml(imported, [host("192.0.2.1", [("tcp", 443, "open")]),
                       host("192.0.2.2", [("udp", 53, "open")])])
        real_run = scan.run

        def fake_run(command, directory, manifest, save, label):
            if command[0] == "xsltproc":
                return real_run(command, directory, manifest, save, label)
            self.assertEqual(command[0], "nmap")
            target = (directory / command[command.index("-iL") + 1]).read_text().strip()
            port_spec = command[command.index("-p") + 1]
            if target == "192.0.2.1":
                self.assertIn("-sT", command)
                self.assertNotIn("-sU", command)
                self.assertEqual(port_spec, "T:443")
                found = [("tcp", 443, "open")]
            else:
                self.assertIn("-sU", command)
                self.assertNotIn("-sT", command)
                self.assertEqual(port_spec, "U:53")
                found = [("udp", 53, "open|filtered")]
            xml(directory / command[command.index("-oX") + 1], [host(target, found)])

        with patch.object(scan.shutil, "which", return_value="/fake/tool"), patch.object(scan, "run", fake_run):
            status = scan.main([str(self.targets), "--masscan-xml", str(imported),
                                "--output-dir", str(self.path / "results"), "--source-zone", "office"])
        self.assertEqual(status, 0)
        directory = next((self.path / "results").iterdir())
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["discovered_hosts"], 2)
        self.assertEqual(manifest["confirmation_states"], {"open": 1, "open|filtered": 1})
        self.assertEqual(len(list(scan.elements(directory / "nmap.xml", "host"))), 2)
        self.assertEqual(manifest["sha256"]["nmap-bootstrap.xsl"], scan.sha256(ROOT / "nmap-bootstrap.xsl"))
        self.assertIn("192.0.2.1", (directory / "nmap-bootstrap.html").read_text())

    def test_failed_scan_retains_evidence(self):
        imported = self.path / "import.xml"
        xml(imported, [host("192.0.2.1", [("tcp", 443, "open")])])
        with patch.object(scan.shutil, "which", return_value="/fake/tool"), patch.object(
                scan, "run", side_effect=RuntimeError("simulated scanner failure")):
            result = scan.main([str(self.targets), "--masscan-xml", str(imported),
                                "--output-dir", str(self.path / "results"), "--skip-html"])
        self.assertEqual(result, 1)
        directory = next((self.path / "results").iterdir())
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "failed")
        self.assertTrue((directory / "masscan.xml").is_file())
        self.assertFalse((directory / "nmap-bootstrap.html").exists())

    def test_process_failure_records_exit_and_log(self):
        manifest = {"commands": []}
        with self.assertRaises(RuntimeError):
            scan.run([sys.executable, "-c", "print('failure details'); raise SystemExit(7)"],
                     self.path, manifest, lambda: None, "failed")
        self.assertEqual(manifest["commands"][0]["returncode"], 7)
        self.assertIn("failure details", (self.path / "failed.log").read_text())

    def test_zero_discovery_skips_nmap(self):
        imported = self.path / "import.xml"
        xml(imported, [])
        with patch.object(scan.shutil, "which", return_value="/fake/tool"), patch.object(scan, "run") as run:
            result = scan.main([str(self.targets), "--masscan-xml", str(imported),
                                "--output-dir", str(self.path / "results"), "--skip-html"])
        self.assertEqual(result, 0)
        run.assert_not_called()
        directory = next((self.path / "results").iterdir())
        self.assertTrue((directory / "endpoint-evidence.csv").is_file())


class RustScanTests(unittest.TestCase):
    setUp = ConversionTests.setUp
    def test_rustscan_scope_subtraction_and_lazy_batches(self):
        self.assertEqual(list(scan.effective_ranges(self.scope, self.scope)), [])
        self.targets.write_text("0.0.0.0/0\n")
        self.normal.write_text("0.0.0.0/0\n")
        excluded = self.path / "excluded.txt"
        excluded.write_text("0.0.0.0/31\n0.0.0.4/30\n")
        args = scan.parser().parse_args([str(self.targets), "--scanner", "rustscan",
                                        "--tcp-ports", "443", "--udp-ports", "none", "--batch-size", "3"])
        jobs = scan.rustscan_jobs(args, self.path, scan.Scope(self.normal), scan.Scope(excluded))
        first, second = next(jobs), next(jobs)
        self.assertEqual(first[3], ["0.0.0.2", "0.0.0.3", "0.0.0.8"])
        self.assertEqual(second[3], ["0.0.0.9", "0.0.0.10", "0.0.0.11"])
        self.assertNotIn("--udp", first[1])

    def test_rustscan_range_and_mixed_port_arguments(self):
        self.assertEqual(list(scan.rustscan_port_options("0-65535")), [["--range", "0-65535"]])
        options = list(scan.rustscan_port_options("0,22,80-82,65535"))
        self.assertEqual(options, [["--ports", "0,22,80,81,82,65535"]])
        chunks = list(scan.rustscan_port_options("0-2000,65535"))
        self.assertTrue(all(len(option[1].split(",")) <= 1000 for option in chunks))
        selected = [int(value) for option in chunks for value in option[1].split(",")]
        self.assertEqual(selected, list(range(2001)) + [65535])

    def test_rustscan_protocol_labels_and_duplicate_output(self):
        path = self.path / "rustscan.stdout"
        path.write_text("192.0.2.1 -> [53,53]\n\n")
        hosts = list(scan.rustscan_hosts(path, "udp", ["192.0.2.1"], ["--ports", "53"]))
        output = self.path / "rustscan.xml"
        xml(output, hosts)
        scan.load_discovery(output, self.db, self.scope)
        self.assertEqual(list(self.db.execute("SELECT * FROM discovered")), [("192.0.2.1", "udp", 53)])

    def test_rustscan_rejects_unexpected_output_hosts_and_ports(self):
        path = self.path / "rustscan.stdout"
        for text in ["Open 192.0.2.1:443", "192.0.2.2 -> [443]", "192.0.2.1 -> [80]",
                     "192.0.2.1 -> [65536]", "192.0.2.1 -> [443,]"]:
            with self.subTest(text=text):
                path.write_text(text + "\n")
                with self.assertRaises(ValueError):
                    list(scan.rustscan_hosts(path, "tcp", ["192.0.2.1"], ["--ports", "443"]))
        path.write_text("")
        self.assertEqual(list(scan.rustscan_hosts(path, "tcp", [], ["--ports", "443"])), [])

    def test_rustscan_rejects_incompatible_source_and_import_options(self):
        for options in [["--interface", "eth0"], ["--source-ip", "192.0.2.1"],
                        ["--masscan-xml", "old.xml"], ["--rustscan-tries", "256"],
                        ["--rustscan-batch-size", "65536"]]:
            with self.subTest(options=options), self.assertRaises(SystemExit) as error:
                scan.main([str(self.targets), "--scanner", "rustscan", "--dry-run"] + options)
            self.assertEqual(error.exception.code, 2)

    def test_environment_backend_selection_and_cli_override(self):
        with patch.dict(os.environ, {"CDESCAN_SCANNER": "rustscan"}):
            self.assertEqual(scan.parser().parse_args([str(self.targets)]).scanner, "rustscan")
            self.assertEqual(scan.parser().parse_args([str(self.targets), "--scanner", "masscan"]).scanner, "masscan")
        with patch.dict(os.environ, {"CDESCAN_SCANNER": "oops"}), self.assertRaises(SystemExit):
            scan.main([str(self.targets), "--dry-run"])

    def test_rustscan_dry_run_does_not_launch_processes(self):
        with patch.object(scan.subprocess, "run") as run:
            status = scan.main([str(self.targets), "--scanner", "rustscan", "--dry-run",
                                "--output-dir", str(self.path / "results")])
        self.assertEqual(status, 0)
        run.assert_not_called()

    def test_rustscan_requires_fixed_udp_version_before_scanning(self):
        with patch.object(scan.shutil, "which", return_value="/fake/tool"), patch.object(
                scan.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "rustscan 2.3.0", "")), patch.object(
                scan, "run") as run:
            status = scan.main([str(self.targets), "--scanner", "rustscan", "--skip-html",
                                "--output-dir", str(self.path / "results")])
        self.assertEqual(status, 1)
        run.assert_not_called()

    def test_rustscan_pipeline_through_real_subprocesses_and_xslt(self):
        binaries = self.path / "bin"
        binaries.mkdir()
        # Stand-in executables exercise argv, stdout/stderr separation and real process handling.
        fixture = '''from pathlib import Path
import sys
import xml.etree.ElementTree as ET
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if '--version' in args:
    print('rustscan 2.4.1' if name == 'rustscan' else 'Nmap fixture 1.0')
elif name == 'rustscan':
    assert '--greppable' in args and '--no-config' in args
    assert args[args.index('--scripts') + 1] == 'none'
    print('diagnostic fixture', file=sys.stderr)
    for address in Path(args[args.index('--addresses') + 1]).read_text().splitlines():
        if '--udp' not in args:
            print(f'{address} -> [443]')
        elif address == '192.0.2.2':
            print(f'{address} -> [53]')
else:
    root = ET.Element('nmaprun')
    for address in Path(args[args.index('-iL') + 1]).read_text().splitlines():
        h = ET.SubElement(root, 'host')
        ET.SubElement(h, 'status', state='up')
        ET.SubElement(h, 'address', addr=address, addrtype='ipv4')
        ports = ET.SubElement(h, 'ports')
        assert '-sT' in args
        ET.SubElement(ET.SubElement(ports, 'port', protocol='tcp', portid='443'), 'state', state='open')
        if '-sU' in args:
            assert address == '192.0.2.2'
            ET.SubElement(ET.SubElement(ports, 'port', protocol='udp', portid='53'), 'state', state='open|filtered')
    ET.SubElement(ET.SubElement(root, 'runstats'), 'finished', exit='success')
    ET.ElementTree(root).write(args[args.index('-oX') + 1])
'''
        for name in ("rustscan", "nmap"):
            path = binaries / name
            path.write_text(f"#!{sys.executable}\n" + fixture)
            path.chmod(0o755)
        self.targets.write_text("192.0.2.0/30\n")
        excluded = self.path / "excluded.txt"
        excluded.write_text("192.0.2.0\n192.0.2.3\n")
        with patch.dict(os.environ, {"PATH": str(binaries) + os.pathsep + os.environ["PATH"]}):
            status = scan.main([str(self.targets), "--scanner", "rustscan", "--tcp-ports", "443",
                                "--udp-ports", "53", "--exclude-file", str(excluded),
                                "--output-dir", str(self.path / "results")])
        self.assertEqual(status, 0)
        directory = next((self.path / "results").iterdir())
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["discovery_backend"], "rustscan")
        self.assertEqual(manifest["discovered_endpoints"], 3)
        self.assertEqual(manifest["confirmation_states"], {"open": 2, "open|filtered": 1})
        self.assertEqual(set(manifest["tools"]), {"rustscan", "nmap", "xsltproc"})
        self.assertIn("diagnostic fixture", next(directory.glob("rustscan-tcp-*.log")).read_text())
        self.assertNotIn("diagnostic", next(directory.glob("rustscan-tcp-*.stdout")).read_text())
        with (directory / "endpoint-evidence.csv").open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertTrue(all(row["rustscan_state"] == "open" for row in rows))
        self.assertFalse((directory / "masscan.xml").exists())
        self.assertTrue((directory / "rustscan-observations.csv").is_file())
        self.assertIn("192.0.2.2", (directory / "nmap-bootstrap.html").read_text())


if __name__ == "__main__":
    unittest.main()
