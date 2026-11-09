#!/usr/bin/env python3
"""Masscan discovery and host-specific Nmap confirmation. Python 3.10+."""

import argparse
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from xml.sax.saxutils import quoteattr

VERSION = "2.0.0"
STYLESHEET_URL = "https://raw.githubusercontent.com/Haxxnet/nmap-bootstrap-xsl/main/nmap-bootstrap.xsl"


def now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def ports(value):
    if value.lower() == "none":
        return ""
    found = set()
    try:
        for part in value.split(","):
            bounds = part.split("-")
            if len(bounds) not in (1, 2):
                raise ValueError()
            first, last = int(bounds[0]), int(bounds[-1])
            if not 0 <= first <= last <= 65535:
                raise ValueError()
            found.update(range(first, last + 1))
    except ValueError:
        raise argparse.ArgumentTypeError("use ports/ranges from 0 to 65535, or 'none'")
    return compress_ports(found)


def compress_ports(values):
    values = sorted(set(values))
    output = []
    for value in values:
        if not output or value != output[-1][1] + 1:
            output.append([value, value])
        else:
            output[-1][1] = value
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in output)


def snapshot_targets(source, destination):
    """Keep CIDRs compact: never expand a large scope into individual IPs."""
    count = 0
    with Path(source).open(encoding="utf-8-sig") as incoming, destination.open("w") as out:
        for number, line in enumerate(incoming, 1):
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
                if network.version != 4:
                    raise ValueError("this Masscan workflow supports IPv4 only")
            except ValueError as error:
                raise ValueError(f"{source}:{number}: {error}") from error
            out.write(str(network) + "\n")
            count += 1
    if count == 0:
        raise ValueError(f"{source}: no IPv4 addresses or CIDRs")
    return count


class Scope:
    """Collapsed integer ranges, with logarithmic membership checks."""

    def __init__(self, path):
        from bisect import bisect_right
        self.search = bisect_right
        with path.open() as stream:
            networks = ipaddress.collapse_addresses(ipaddress.ip_network(line.strip()) for line in stream)
            self.ranges = [(int(n.network_address), int(n.broadcast_address)) for n in networks]
        self.starts = [first for first, _ in self.ranges]

    def __contains__(self, address):
        value = int(ipaddress.ip_address(address))
        index = self.search(self.starts, value) - 1
        return index >= 0 and value <= self.ranges[index][1]


def elements(path, tag):
    """Stream direct children of nmaprun and release processed XML nodes."""
    with Path(path).open("rb") as stream:
        context = ET.iterparse(stream, events=("start", "end"))
        try:
            event, root = next(context)
            if root.tag != "nmaprun":
                raise ValueError(f"{path}: expected an nmaprun XML document")
            depth = 0
            for event, element in context:
                if event == "start":
                    depth += 1
                else:
                    if depth == 1:
                        if tag is None or element.tag == tag:
                            yield element
                        root.remove(element)
                    depth -= 1
        finally:
            close = getattr(context, "close", None)
            if close is not None:
                close()


def host_ip(host):
    address = host.find("address[@addrtype='ipv4']")
    if address is None:
        address = host.find("address")
    if address is None:
        raise ValueError("XML host missing an address")
    return str(ipaddress.IPv4Address(address.attrib["addr"]))


def load_discovery(path, database, scope, excluded=None):
    database.execute("CREATE TABLE discovered (ip TEXT, protocol TEXT, port INTEGER, "
                     "PRIMARY KEY(ip, protocol, port)) WITHOUT ROWID")
    hosts = 0
    for host in elements(path, "host"):
        address = host_ip(host)
        if address not in scope or (excluded is not None and address in excluded):
            raise ValueError(f"discovery contains an out-of-scope/excluded address: {address}")
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            protocol, number = port.get("protocol"), int(port.attrib["portid"])
            if protocol not in ("tcp", "udp") or not 0 <= number <= 65535:
                raise ValueError("invalid discovery port/protocol")
            database.execute("INSERT OR IGNORE INTO discovered VALUES (?, ?, ?)",
                             (address, protocol, number))
        hosts += 1
        if hosts % 1000 == 0:
            database.commit()
    database.commit()


def batches(database, size):
    cursor = database.execute("SELECT ip, protocol, port FROM discovered ORDER BY ip, protocol, port")
    batch = {}
    for address, protocol, port in cursor:
        if address not in batch and len(batch) >= size:
            yield batch
            batch = {}
        batch.setdefault(address, {"tcp": [], "udp": []})[protocol].append(port)
    if batch:
        yield batch


def plans(database, size):
    """Only hosts with identical port sets share a scan; keep each batch bounded."""
    for batch in batches(database, size):
        groups = {}
        for address, found in batch.items():
            signature = (compress_ports(found["tcp"]), compress_ports(found["udp"]))
            groups.setdefault(signature, []).append(address)
        yield from groups.items()


def run(command, directory, manifest, save, label):
    record = {"argv": command, "started": now(), "log": f"{label}.log"}
    manifest["commands"].append(record)
    save()
    print("+", shlex.join(command), flush=True)
    try:
        with (directory / record["log"]).open("w") as log:
            result = subprocess.run(command, cwd=directory, stdout=log, stderr=subprocess.STDOUT,
                                    check=False)
        record["returncode"] = result.returncode
        if result.returncode:
            raise RuntimeError(f"{label} exited {result.returncode}; see {directory / record['log']}")
    finally:
        record["finished"] = now()
        save()


def merge_reports(paths, destination, started):
    counts = {"up": 0, "down": 0, "total": 0}
    with destination.open("wb") as stream:
        attrs = {"scanner": "nmap", "start": str(int(started)),
                 "startstr": datetime.fromtimestamp(started, timezone.utc).isoformat(),
                 "args": "cdescan: aggregate of Nmap jobs; see manifest.json for exact commands",
                 "version": "aggregated", "xmloutputversion": "1.05"}
        stream.write(('<?xml version="1.0" encoding="utf-8"?>\n<nmaprun ' +
                      " ".join(f"{key}={quoteattr(value)}" for key, value in attrs.items()) +
                      ">\n").encode())
        for path in paths:
            complete = False
            for host in elements(path, None):
                if host.tag == "runstats":
                    finished = host.find("finished")
                    complete = finished is not None and finished.get("exit") == "success"
                    continue
                if host.tag != "host":
                    continue
                status = host.find("status")
                counts["total"] += 1
                if status is not None and status.get("state") in ("up", "down"):
                    counts[status.get("state")] += 1
                stream.write(ET.tostring(host, encoding="utf-8"))
                stream.write(b"\n")
            if not complete:
                raise RuntimeError(f"Nmap completion marker missing or unsuccessful: {path}")
        stats = ET.Element("runstats")
        ET.SubElement(stats, "finished", time=str(int(time.time())), timestr=now(),
                      elapsed=f"{time.time() - started:.2f}", exit="success",
                      summary="Confirmation hosts only; not the full target scope")
        ET.SubElement(stats, "hosts", **{key: str(value) for key, value in counts.items()})
        stream.write(ET.tostring(stats, encoding="utf-8"))
        stream.write(b"\n</nmaprun>\n")
    return counts


def export_csv(database, report, directory):
    with (directory / "masscan-observations.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["ip", "protocol", "port", "state"])
        for row in database.execute("SELECT ip, protocol, port FROM discovered ORDER BY ip, protocol, port"):
            writer.writerow((*row, "open"))
    database.execute("CREATE TABLE confirmed (ip TEXT, protocol TEXT, port INTEGER, state TEXT, "
                     "PRIMARY KEY(ip, protocol, port)) WITHOUT ROWID")
    with (directory / "nmap-observations.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["ip", "protocol", "port", "state", "reason", "service", "product", "version"])
        for host in elements(report, "host"):
            address = host_ip(host)
            for port in host.findall("ports/port"):
                state, service = port.find("state"), port.find("service")
                state = state.attrib if state is not None else {}
                service = service.attrib if service is not None else {}
                number, protocol = int(port.attrib["portid"]), port.attrib["protocol"]
                writer.writerow([address, protocol, number, state.get("state", "unknown"),
                                 state.get("reason", ""), service.get("name", ""),
                                 service.get("product", ""), service.get("version", "")])
                database.execute("INSERT OR REPLACE INTO confirmed VALUES (?, ?, ?, ?)",
                                 (address, protocol, number, state.get("state", "unknown")))
    database.commit()
    # Nmap can collapse closed/filtered ports into extraports or omit timed-out hosts.
    # Preserve a row for EVERY discovered endpoint; don't infer omitted port states.
    with (directory / "endpoint-evidence.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["ip", "protocol", "port", "masscan_state", "nmap_state"])
        rows = database.execute("SELECT d.ip,d.protocol,d.port,COALESCE(c.state,'not_individually_reported') "
                                "FROM discovered d LEFT JOIN confirmed c USING(ip,protocol,port) "
                                "ORDER BY d.ip,d.protocol,d.port")
        for address, protocol, port, state in rows:
            writer.writerow([address, protocol, port, "open", state])


def parser():
    cli = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    cli.add_argument("targets", type=Path, help="IPv4 addresses/CIDRs, one per line; # comments accepted")
    cli.add_argument("--version", action="version", version=VERSION)
    cli.add_argument("--output-dir", type=Path, default=Path("results"), help="parent for a unique evidence directory")
    cli.add_argument("--tcp-ports", type=ports, default="0-65535", help="Masscan TCP ports or none")
    cli.add_argument("--udp-ports", type=ports, default="0-65535", help="Masscan UDP ports or none")
    cli.add_argument("--rate", type=positive, default=10000, help="Masscan packets/second")
    cli.add_argument("--wait", type=positive, default=10, help="Masscan final response wait in seconds")
    cli.add_argument("--exclude-file", type=Path, help="IPv4 addresses/CIDRs to exclude")
    cli.add_argument("--interface", help="outgoing interface for both scanners")
    cli.add_argument("--source-ip", type=ipaddress.IPv4Address, help="local source IPv4 for both scanners")
    cli.add_argument("--source-zone", default="", help="assessment vantage-point label")
    cli.add_argument("--destination-zone", default="", help="destination scope label")
    cli.add_argument("--assessment-id", default="", help="assessment/change/ticket reference")
    cli.add_argument("--batch-size", type=positive, default=128, help="maximum hosts per Nmap job")
    cli.add_argument("--tcp-scan", choices=("connect", "syn"), default="connect")
    cli.add_argument("--timing", type=int, choices=range(6), default=4, help="Nmap timing template")
    cli.add_argument("--max-retries", type=int, default=2, help="Nmap retries; nonnegative")
    cli.add_argument("--host-timeout", type=positive, help="optional Nmap per-host timeout in seconds")
    cli.add_argument("--service-version", action="store_true", help="enable active Nmap -sV probes")
    cli.add_argument("--masscan-xml", type=Path, help="reuse discovery XML instead of running Masscan")
    cli.add_argument("--stylesheet", type=Path, default=Path(__file__).resolve().with_name("nmap-bootstrap.xsl"))
    cli.add_argument("--native-stylesheet", type=Path, help="also generate native HTML using a local nmap.xsl")
    cli.add_argument("--skip-html", action="store_true", help="produce XML/CSV evidence only")
    cli.add_argument("--dry-run", action="store_true", help="validate inputs and print discovery command without scanning")
    return cli


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    if not args.tcp_ports and not args.udp_ports:
        cli.error("at least one protocol must have ports")
    if args.max_retries < 0:
        cli.error("--max-retries must be nonnegative")
    if args.source_ip and not args.interface:
        cli.error("--source-ip requires --interface")
    args.output_dir = args.output_dir.resolve()
    for name in ("targets", "exclude_file", "masscan_xml", "stylesheet", "native_stylesheet"):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, value.resolve())
    required = [] if args.dry_run else ["nmap"]
    if not args.masscan_xml and not args.dry_run:
        required.append("masscan")
    if not args.skip_html and not args.dry_run:
        required.append("xsltproc")
        if not args.stylesheet.is_file():
            cli.error(f"missing stylesheet: {args.stylesheet}; obtain {STYLESHEET_URL}")
        if args.native_stylesheet and not args.native_stylesheet.is_file():
            cli.error(f"missing native stylesheet: {args.native_stylesheet}")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        cli.error("missing executables: " + ", ".join(missing))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = args.output_dir / f"{stamp}-{uuid.uuid4().hex[:8]}"
    directory.mkdir(parents=True)
    manifest = {"version": VERSION, "started": now(), "status": "running", "hostname": socket.gethostname(),
                "settings": {key: str(value) if isinstance(value, (Path, ipaddress.IPv4Address)) else value
                             for key, value in vars(args).items()}, "commands": [],
                "interpretation": "Discovery-led observations only. Silence and open|filtered do not establish "
                                  "segmentation. No automatic PCI compliance determination."}

    def save():
        temporary = directory / "manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2) + "\n")
        temporary.replace(directory / "manifest.json")

    database = None
    started = time.time()
    save()
    try:
        snapshot_targets(args.targets, directory / "targets.txt")
        scope = Scope(directory / "targets.txt")
        excluded = None
        if args.exclude_file:
            snapshot_targets(args.exclude_file, directory / "excluded.txt")
            excluded = Scope(directory / "excluded.txt")
        discovery = directory / "masscan.xml"
        port_spec = ",".join(value for value in
                             (args.tcp_ports, f"U:{args.udp_ports}" if args.udp_ports else "") if value)
        command = ["masscan", "-v", "-p", port_spec, "--rate", str(args.rate),
                   "--wait", str(args.wait), "--open-only", "-iL", "targets.txt", "-oX", "masscan.xml"]
        if args.exclude_file:
            command += ["--excludefile", "excluded.txt"]
        if args.interface:
            command += ["--adapter", args.interface]
        if args.source_ip:
            command += ["--adapter-ip", str(args.source_ip)]
        if args.dry_run:
            if args.masscan_xml:
                print(f"Reuse discovery: {args.masscan_xml}")
            else:
                print(shlex.join(command))
            print("Nmap jobs are determined by discovered host-specific TCP/UDP ports.")
            manifest["status"] = "dry-run"
            return 0
        for tool in required:
            probe = [tool, "--version"]
            result = subprocess.run(probe, capture_output=True, text=True, check=False)
            manifest.setdefault("tools", {})[tool] = {"path": shutil.which(tool),
                                                       "version": (result.stdout + result.stderr).strip()}
        if not args.skip_html:
            shutil.copyfile(args.stylesheet, directory / "nmap-bootstrap.xsl")
            manifest["stylesheet_source"] = STYLESHEET_URL if args.stylesheet == parser().get_default("stylesheet") else str(args.stylesheet)
        if args.masscan_xml:
            shutil.copyfile(args.masscan_xml, discovery)
        else:
            run(command, directory, manifest, save, "masscan")
            if (directory / "paused.conf").exists():
                raise RuntimeError("Masscan saved paused.conf; discovery is incomplete")
        database = sqlite3.connect(directory / "evidence.sqlite3")
        load_discovery(discovery, database, scope, excluded)
        manifest["discovered_hosts"] = database.execute("SELECT COUNT(DISTINCT ip) FROM discovered").fetchone()[0]
        manifest["discovered_endpoints"] = database.execute("SELECT COUNT(*) FROM discovered").fetchone()[0]
        save()
        outputs = []
        for index, ((tcp, udp), addresses) in enumerate(plans(database, args.batch_size), 1):
            label = f"nmap-{index:06d}"
            (directory / f"{label}.targets").write_text("\n".join(addresses) + "\n")
            cmd = ["nmap", "-Pn", "-n", f"-T{args.timing}", "--max-retries", str(args.max_retries),
                   "--reason", "-v", "-iL", f"{label}.targets", "-oX", f"{label}.xml"]
            if tcp:
                cmd += ["-sT" if args.tcp_scan == "connect" else "-sS"]
            if udp:
                cmd += ["-sU"]
            cmd += ["-p", ",".join(f"{p}:{v}" for p, v in (("T", tcp), ("U", udp)) if v)]
            if args.interface:
                cmd += ["-e", args.interface]
            if args.source_ip:
                cmd += ["-S", str(args.source_ip)]
            if args.host_timeout:
                cmd += ["--host-timeout", f"{args.host_timeout}s"]
            if args.service_version:
                cmd += ["-sV"]
            run(cmd, directory, manifest, save, label)
            outputs.append(directory / f"{label}.xml")
        manifest["nmap_hosts"] = merge_reports(outputs, directory / "nmap.xml", started)
        export_csv(database, directory / "nmap.xml", directory)
        manifest["confirmation_states"] = dict(database.execute(
            "SELECT COALESCE(c.state,'not_individually_reported'),COUNT(*) "
            "FROM discovered d LEFT JOIN confirmed c USING(ip,protocol,port) "
            "GROUP BY COALESCE(c.state,'not_individually_reported')"))
        if not args.skip_html:
            run(["xsltproc", "--nonet", "-o", "nmap-bootstrap.html", "nmap-bootstrap.xsl", "nmap.xml"],
                directory, manifest, save, "bootstrap-report")
            if args.native_stylesheet:
                shutil.copyfile(args.native_stylesheet, directory / "nmap-native.xsl")
                run(["xsltproc", "--nonet", "-o", "nmap-native.html", "nmap-native.xsl", "nmap.xml"],
                    directory, manifest, save, "native-report")
        manifest["status"] = "complete"
        print(f"Evidence and reports: {directory}")
        print("Review both discovery and confirmation evidence; silence is inconclusive.")
        return 0
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        print(f"Interrupted; partial evidence retained at {directory}", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, ET.ParseError, sqlite3.Error) as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        print(f"ERROR: {error}\nPartial evidence: {directory}", file=sys.stderr)
        return 1
    finally:
        if database is not None:
            database.close()
        manifest["finished"] = now()
        manifest["sha256"] = {str(path.relative_to(directory)): sha256(path)
                              for path in directory.rglob("*") if path.is_file()
                              and path.name not in ("manifest.json", "manifest.json.tmp")}
        save()


if __name__ == "__main__":
    sys.exit(main())
