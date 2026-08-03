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
- Skips malformed or unreadable files instead of aborting the whole run
- Verbose logging for troubleshooting

## Requirements

- Python 3 (standard library only — no dependencies to install)

## Usage

```bash
python3 nessmerge.py [-d directory_with_.nessus_files] [-o output_path] [-r] [-v]
```

### Options

| Flag | Long form | Description |
|---|---|---|
| `-d` | `--dir` | Directory containing `.nessus` files to merge (default: the directory this script is located in) |
| `-o` | `--output` | Output file path (default: `nss_report/report.nessus`) |
| `-r` | `--recursive` | Also search subdirectories, not just the top level |
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

## How merging works

1. The first successfully-parsed `.nessus` file becomes the base report (renamed to `Merged Report`).
2. For each subsequent file:
   - Hosts not already present (matched by `name`) are appended as-is.
   - For hosts that already exist, individual findings (matched by `port` + `pluginID`) are added only if not already present.
3. Files that fail to parse (malformed XML, missing `<Report>` element, unreadable file) are logged and skipped — they don't stop the merge.
4. A summary of any skipped files is printed at the end of the run.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | No `.nessus` files found, or none could be parsed |
| `2` | Target directory does not exist |

## Notes

- Output directory is created automatically if it doesn't exist.
- This tool does not modify or delete the original scan files.