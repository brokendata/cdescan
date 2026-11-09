# Changelog

## 2.1.0

- Add selectable discovery through `--scanner masscan|rustscan` or
  `CDESCAN_SCANNER`; Masscan remains the default.
- Add RustScan 2.4.1+ TCP/UDP discovery with bounded host batches and
  configurable socket concurrency, timeout, and attempts.
- Apply exclusions before RustScan probes, disable its automatic scripting,
  and retain raw stdout, stderr, and normalized XML/CSV evidence.
- Reject unsupported interface/source-IP controls in RustScan mode and check
  returned addresses and ports against the exact job scope.
- Preserve the existing Masscan workflow and its evidence column names.
- Expand validation to 21 tests, including simulated RustScan/Nmap executables
  and real XSLT report generation. Live RustScan execution remains unverified.

## 2.0.0

- Convert the original shell scanner to a Python 3.10+ CLI.
- Add host-specific Nmap confirmation and bounded batching.
- Integrate the Haxxnet Bootstrap stylesheet and preserve XML/CSV evidence,
  scan context, timestamps, command logs, and file hashes.
