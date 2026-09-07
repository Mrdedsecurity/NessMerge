```
 _   _              __  __
| \ | | ___  ___ ___|  \/  | ___ _ __ __ _  ___
|  \| |/ _ \/ __/ __| |\/| |/ _ \ '__/ _` |/ _ \
| |\  |  __/\__ \__ \ |  | |  __/ | | (_| |  __/
|_| \_|\___||___/___/_|  |_|\___|_|  \__, |\___|
                                      |___/
        merge .nessus scans into one report
                                       By MrDedSec
```

Merge multiple `.nessus` (Nessus XML) scan result files into a single combined report.

## Features

- Merges all `.nessus` files in a directory into one report
- Deduplicates hosts by name and findings by port + plugin ID, so re-scans of the same target don't produce duplicate entries
- Recursive directory search (`-r`)
- Optional extraction of every unique host IP in the merged report into a plain-text file
Recursive directory search (-r)
- Skips malformed or unreadable files instead of aborting the whole run
- Verbose logging for troubleshooting

## Requirements

- Python 3 (standard library only — no dependencies to install)

## Usage

```bash
python3 nessmerge.py [-d directory_with_.nessus_files] [-o output_path] [-r] [-v] [--extract-ips] [--ips-output path]
```

### Options

| Flag | Long form | Description |
|---|---|---|
| `-d` | `--dir` | Directory containing `.nessus` files to merge (default: the directory this script is located in) |
| `-o` | `--output` | Output file path (default: `nss_report/report.nessus`) |
| `-r` | `--recursive` | Also search subdirectories, not just the top level |
|  | `--extract-ips` | After merging, write a plain-text list of unique host IPs from the report |
|  | `--ips-output` | Output file path for extracted IPs (default: `nss_report/ips.txt`). Passing this implies `--extract-ips`, so you don't need both |
| `-v` | `--verbose` | Enable debug-level logging |
| `-h` | `--help` | Show usage and exit |

### Examples
Merge everything in the same folder as the script into the default output location:
```bash
python3 nessmerge.py
```
 
Merge everything in `./scans` into the default output location:
```bash
python3 nessmerge.py -d ./scans
```
 
Merge recursively, with a custom output path and verbose logging:
```bash
python3 nessmerge.py -d ./scans -r -o ./merged/final_report.nessus -v
```
 
Merge and also extract every unique host IP to `nss_report/ips.txt`:
```bash
python3 nessmerge.py -d ./scans --extract-ips
```
 
Merge and extract IPs to a custom path in one step:
```bash
python3 nessmerge.py -d ./scans --ips-output results/hosts.txt
```
 
## How merging works
1. The first successfully-parsed `.nessus` file becomes the base report (renamed to `Merged Report`).
2. For each subsequent file:
   - Hosts not already present (matched by `name`) are appended as-is.
   - For hosts that already exist, individual findings (matched by `port` + `pluginID`) are added only if not already present.
3. Files that fail to parse (malformed XML, missing `<Report>` element, unreadable file) are logged and skipped — they don't stop the merge.
4. A summary of any skipped files is printed at the end of the run.
## How IP extraction works
When `--extract-ips` (or a custom `--ips-output`) is used, the script walks every `ReportHost` in the merged report and collects:
- The `host-ip` tag inside that host's `HostProperties` block, if present (this is the canonical IP Nessus records for the host), or
- The host's `name` attribute as a fallback, for hosts identified by hostname rather than IP.
The resulting unique values are sorted and written one per line to the output file (`nss_report/ips.txt` by default).
 
## Exit codes
| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | No `.nessus` files found, or none could be parsed |
| `2` | Target directory does not exist |
 
## Notes
- Output directories are created automatically if they don't exist.
- This tool does not modify or delete the original scan files.
