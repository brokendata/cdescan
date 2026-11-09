# cdescan 2.0 — Python conversion

cdescan helps you check which services are reachable across network segments,
whether you're validating PCI segmentation or surveying a large network. It
combines Masscan's fast discovery with focused Nmap follow-up, then brings the
results together in a readable HTML report using the
[Haxxnet stylesheet](https://github.com/Haxxnet/nmap-bootstrap-xsl). Scan logs,
XML, and CSV exports keep the evidence handy for investigation and reporting.

This Python 3.10+ version builds on Chris Timmons's original `cdescan.sh` and
uses only Python's standard library alongside the external scanning tools.

## Requirements and quick start

Install Python 3.10+, Masscan, Nmap, and xsltproc on the scan host. For example,
on Debian/Kali:

```sh
sudo apt install python3 masscan nmap xsltproc
```

Keep `cdescan.py` and `nmap-bootstrap.xsl` together. Create `targets.txt` with one
IPv4 address or CIDR per line. Blank lines and `#` comments are accepted:

```text
# Destination CDE scope
10.20.0.0/16
10.30.40.10
```

Validate scope and preview discovery without transmitting probes:

```sh
python3 cdescan.py targets.txt --dry-run
```

Run the original all-port TCP/UDP workflow:

```sh
sudo python3 cdescan.py targets.txt
```

As before, the defaults discover TCP and UDP ports **0–65535** at **10,000
packets/second**, then use Nmap TCP connect and UDP scans with `-Pn -n -T4`.
The final Masscan receive wait is now **10 seconds**, replacing `--wait 0`.
Nmap retries default to 2; no per-host timeout is imposed unless requested.
Raw packet operations require the platform's appropriate privileges, usually
root for Masscan, Nmap UDP, and Nmap SYN scans.

Example with assessment context, exclusions, and a lower discovery rate:

```sh
sudo python3 cdescan.py targets.txt \
  --exclude-file excluded.txt \
  --rate 2000 --wait 15 \
  --interface eth0 --source-ip 10.10.5.25 \
  --source-zone corporate --destination-zone CDE \
  --assessment-id SEG-2026-11 \
  --output-dir ./results
```

`--source-ip` must be an address actually assigned to the selected interface.
It requires `--interface`. Zone names are evidence labels; they do not change
routing or discover the true network vantage point. Confirm routing and the
source seen at the destination independently, particularly across NAT.

Other useful options:

```sh
# TCP only, all TCP ports; no Nmap UDP scan
sudo python3 cdescan.py targets.txt --udp-ports none

# Explicit port subset
sudo python3 cdescan.py targets.txt --tcp-ports 22,80,443,1433,3389 --udp-ports 53,123,161

# SYN confirmation with optional active service/version probes
sudo python3 cdescan.py targets.txt --tcp-scan syn --service-version

# Repeat confirmation using existing discovery, without rerunning Masscan
sudo python3 cdescan.py targets.txt --masscan-xml /path/to/previous/masscan.xml

# XML/CSV only, without xsltproc or HTML
sudo python3 cdescan.py targets.txt --skip-html

# Also create native Nmap HTML using an explicitly selected local stylesheet
sudo python3 cdescan.py targets.txt --native-stylesheet /usr/share/nmap/nmap.xsl
```

Use `--help` for all options. Reused discovery is checked against the supplied
scope and exclusions before confirmation. Imported XML determines the ports
to confirm; `--tcp-ports` and `--udp-ports` control a new discovery scan only.
Reuse records a new vantage point and new timestamps; it is not a continuation
of the previous scan. Results always go into a new directory.

## Large-network behavior

- CIDRs remain compact; Python does not enumerate every address in scope.
- Discovery XML is parsed incrementally into a disk-backed SQLite index,
  deduplicating repeated IP/protocol/port observations.
- Nmap jobs group hosts with identical discovered TCP/UDP port sets. Each job
  contains at most `--batch-size` hosts (default 128). A port found on one host
  is not automatically scanned on all other hosts.
- Jobs run sequentially. Highly varied host port sets can create many jobs;
  SQLite, evidence files, and HTML generation still need disk and memory
  proportional to the observed results. xsltproc and the HTML browser may be
  the limiting factors for very large reports; `--skip-html` keeps XML/CSV.
- `--rate` limits Masscan only. Nmap uses its own timing/retry controls.
  `--timing`, `--max-retries`, and `--host-timeout` expose those tradeoffs;
  aggressive timing and short timeouts can lose evidence.

## Evidence files

Each run creates `results/<UTC timestamp>-<unique suffix>/` containing:

| File | Purpose |
| --- | --- |
| `targets.txt`, `excluded.txt` | Normalized scope snapshots; exclusion file when supplied |
| `masscan.xml` | Raw discovery XML, or a copy of imported discovery |
| `nmap-*.targets`, `nmap-*.xml`, `nmap-*.log` | Exact confirmation batches, raw XML, and scanner logs |
| `nmap.xml` | Aggregate confirmation hosts and their port observations |
| `nmap-bootstrap.html` | Haxxnet HTML report, unless skipped |
| `nmap-native.html` | Optional native report |
| `masscan-observations.csv` | Every distinct discovery endpoint |
| `nmap-observations.csv` | Every individually reported confirmation port, including ambiguous/closed/filtered states |
| `endpoint-evidence.csv` | Discovery joined to confirmation; discovery evidence survives confirmation omissions |
| `evidence.sqlite3` | Disk-backed endpoint index |
| `manifest.json` | Context, UTC timestamps, settings, tool versions, command arguments, exit codes, outcome, counts, and SHA-256 hashes |

The aggregate XML contains host records; per-job XML retains scan metadata,
task events, and completion markers. HTML host counts describe confirmation
hosts, not the number of addresses in the original target CIDRs. Some upstream
tables focus on open ports; use XML and CSV for other states. The aggregate's
start/finish span is the workflow duration, including discovery. The manifest
has exact per-command timestamps. Hashes help detect file changes but do not
provide signed evidence or independent chain of custody.

Scanner failures, malformed XML, and Ctrl-C retain partial output. Exit codes:
0 completed workflow or dry run; 1 runtime failure; 2 argument/dependency error;
130 interrupted. A completed workflow does not mean every host responded.
Masscan's `paused.conf`, if produced, stays inside that run directory. There is
no automatic resume; `--masscan-xml` reuses **completed** discovery only.
A newly produced `paused.conf` is treated as incomplete discovery and stops
confirmation. Imported XML cannot establish whether its original scope finished.

## Segmentation interpretation

This preserves the original **discovery-led** design. Endpoints that do not
answer Masscan are not passed to Nmap. It provides positive reachability
evidence, but an empty scan does not establish isolation: silent services,
packet loss, host availability, probe payloads, rate limiting, and UDP response
behavior affect discovery. A port shown as `open|filtered` is unresolved.
`not_individually_reported` means Nmap omitted the endpoint's explicit state
(for example, collapsed ports or a timed-out host), not that it was blocked.
Nmap `-Pn` host status `up` is an assumption, not independent proof of liveness.
Without `--service-version`, service names can be inferred from port numbers.

For assessment coverage, run from each relevant source segment/direction,
retain the intended allow/deny matrix, independently validate known live
listeners and routing, and investigate unexpected observations. This CLI does
not perform that policy comparison, direct confirmation of undiscovered
endpoints, IPv6 testing, non-TCP/UDP protocol testing, or application-layer
segmentation testing. It makes no automatic PCI pass/fail determination.

## Stylesheet provenance

`nmap-bootstrap.xsl` is an unmodified download from:

https://raw.githubusercontent.com/Haxxnet/nmap-bootstrap-xsl/main/nmap-bootstrap.xsl

Retrieved November 9, 2026. SHA-256:

```text
3bded9dd837b7a829b3b58ea48d04565b1a81461baa510e0c3b9d9f7bcf757e1
```

Its author notices are preserved, including its stated restriction on military
or secret-service use. The upstream template loads JavaScript/CSS from public
CDNs; offline interactive features depend on those assets being available.
It also includes links to external services. The CLI itself uses the local
stylesheet and `xsltproc --nonet`; it does not fetch a stylesheet during scans.
For an update, replace the local XSL with a reviewed upstream revision or pass
`--stylesheet /path/to/nmap-bootstrap.xsl`. Each run snapshots and hashes it.

## Validation

```sh
python3 -m unittest discover -s tests -v
```

Tests use synthetic XML and simulated scanners, plus the real local xsltproc
for populated and empty reports. They check host-specific batching,
deduplication, scope/exclusion enforcement, malformed input, ambiguous and
omitted states, failed/incomplete jobs, and evidence preservation. No live
network scans are required by the tests.
