# cdescan

🔎 Check which services are reachable across network segments for PCI segmentation
validation and large-network assessments. cdescan combines Masscan or RustScan
discovery with focused Nmap confirmation, readable HTML reports, and XML/CSV evidence.

## 🚀 Quick start

Use Linux or macOS with Python 3.10+, Nmap, xsltproc, and your chosen discovery
backend. Python needs no third-party packages. On Debian/Kali:

```sh
sudo apt install python3 masscan rustscan nmap xsltproc
```

Keep `cdescan.py` and `nmap-bootstrap.xsl` together. Create `targets.txt` with one
IPv4 address or CIDR per line; blank lines and `#` comments are accepted:

```text
10.20.0.0/16
10.30.40.10
```

```sh
# Preview without scanning
python3 cdescan.py targets.txt --dry-run

# Scan with Masscan (default)
sudo python3 cdescan.py targets.txt

# Select RustScan, using the option or an environment variable
sudo python3 cdescan.py targets.txt --scanner rustscan
sudo env CDESCAN_SCANNER=rustscan python3 cdescan.py targets.txt
```

Defaults scan TCP and UDP ports **0–65535**. Masscan uses **10,000 packets/sec**;
RustScan requires **2.4.1+** and uses socket concurrency instead of a packet rate.
Only the selected discovery backend needs to be installed.

## ⚙️ Common options

```sh
# Lower Masscan's rate and apply exclusions
sudo python3 cdescan.py targets.txt --rate 1000 --exclude-file excluded.txt

# Limit ports, or use --udp-ports none for TCP only
sudo python3 cdescan.py targets.txt --tcp-ports 22,80,443 --udp-ports 53,161

# Lower RustScan concurrency
sudo python3 cdescan.py targets.txt --scanner rustscan --rustscan-batch-size 128

# Reuse completed Masscan discovery for fresh Nmap confirmation
sudo python3 cdescan.py targets.txt --masscan-xml previous/masscan.xml
```

Use `--help` for assessment labels, service/version probes, timing controls,
and output options. `--interface` and `--source-ip` work with Masscan/Nmap;
they are unavailable in RustScan mode. `--rate` and `--wait` apply only to Masscan.

## ⏸️ Pause and resume

Press **Ctrl-C once** and allow the scanner to finish saving its state. Resume
on the original scan host, without supplying a targets file:

```sh
# Continue a Masscan run at 1,000 packets/sec
sudo python3 cdescan.py --resume results/RUN_DIRECTORY --rate 1000

# Continue a RustScan run with lower concurrency
sudo python3 cdescan.py --resume results/RUN_DIRECTORY --rustscan-batch-size 128

# Preview a resume without scanning
sudo python3 cdescan.py --resume results/RUN_DIRECTORY --dry-run
```

Resume requires a run started with **cdescan 2.2.0+**. It preserves earlier
findings, reuses verified completed jobs, and retries incomplete jobs. Masscan
uses its native checkpoint; RustScan and Nmap resume at job boundaries.

Keep the entire run directory intact. Saved scope, ports, backend, and scan mode
cannot change during resume; speed/timing settings can. Masscan needs a usable
checkpoint—forced stops or power loss may require a new run.

## 📁 Results

Each new run gets a directory under `results/` containing HTML reports, XML/CSV
observations, raw scanner attempts, logs, a SQLite index, and `manifest.json`
with settings, timestamps, command history, and hashes. Resume continues there
and retains prior attempts. Use `--skip-html` for XML/CSV-only output.

Hosts share Nmap jobs only when their discovered port sets match. Host batches
are bounded with `--batch-size` (default **128**); jobs run sequentially.

> **Segmentation evidence:** only discovered endpoints receive Nmap follow-up.
> Silence does not prove isolation, and ambiguous states remain unresolved.
> cdescan does not issue a PCI pass/fail decision; validate coverage from the
> relevant source segments and compare observations with the intended policy.

## 🕰️ History and releases

cdescan began as Chris Timmons's **Bash script, `cdescan.sh` (v1.3)**, heavily
adapted from [MassMap](https://github.com/capt-meelo/MassMap). It automated
Masscan TCP/UDP discovery, extracted hosts and ports with shell tools, passed
them to Nmap, and generated native and Bootstrap HTML reports. The Python
rewrite kept that practical workflow while adding host-specific confirmation,
structured evidence, a choice of discovery tools, and resumable runs.

| Version | What changed |
| --- | --- |
| **1.3 · Bash** | Original Masscan → Nmap → HTML reporting workflow. |
| [**2.0.0**](https://github.com/brokendata/cdescan/releases/tag/v2.0.0) | Python rewrite, host-specific batching, Haxxnet reports, and XML/CSV evidence. |
| [**2.1.0**](https://github.com/brokendata/cdescan/releases/tag/v2.1.0) | Selectable RustScan TCP/UDP discovery and backend-specific tuning. |
| [**2.2.0**](https://github.com/brokendata/cdescan/releases/tag/v2.2.0) | Resume with speed changes, completed-job reuse, graceful stopping, and evidence checks. |

See [CHANGELOG.md](CHANGELOG.md) for full release notes.

## 🧪 Tests and credits

```sh
python3 -m unittest discover -s tests -v
```

The 35-test suite covers discovery, reporting, and resume behavior using
simulated scanners and real XSLT processing. Live scanning and native Masscan
resume remain unverified in the development environment.

HTML reports use the bundled [Haxxnet nmap-bootstrap-xsl](https://github.com/Haxxnet/nmap-bootstrap-xsl).
Its upstream notices, including the military/secret-service usage restriction,
are preserved. Interactive reports load JavaScript/CSS from public CDNs.
