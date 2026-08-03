#!/usr/bin/env python3

import argparse
import logging
import shutil
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

logger = logging.getLogger("nessmerge")

BANNER = r"""
 _   _              __  __
| \ | | ___  ___ ___|  \/  | ___ _ __ __ _  ___
|  \| |/ _ \/ __/ __| |\/| |/ _ \ '__/ _` |/ _ \
| |\  |  __/\__ \__ \ |  | |  __/ | | (_| |  __/
|_| \_|\___||___/___/_|  |_|\___|_|  \__, |\___|
                                      |___/
        merge .nessus scans into one report
"""


def print_banner():
    print(BANNER)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Merge .nessus scan files found in a directory into one report."
    )
    parser.add_argument(
        "-d", "--dir",
        required=True,
        type=Path,
        help="Directory containing .nessus files to merge",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("nss_report/report.nessus"),
        help="Output file path (default: nss_report/report.nessus)",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Search subdirectories recursively for .nessus files",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (debug) logging",
    )
    return parser.parse_args(argv)


def find_report_host(report, host_name):
    """Find a ReportHost element by name attribute without building unsafe XPath strings."""
    for host in report.findall("ReportHost"):
        if host.attrib.get("name") == host_name:
            return host
    return None


def find_report_item(host, port, plugin_id):
    """Find a ReportItem element by port + pluginID without building unsafe XPath strings."""
    for item in host.findall("ReportItem"):
        if item.attrib.get("port") == port and item.attrib.get("pluginID") == plugin_id:
            return item
    return None


def merge_nessus_files(nessus_files):
    """Merge a list of .nessus file paths into a single ElementTree. Returns the merged tree.

    Files that fail to parse (malformed XML, unreadable, etc.) are logged and
    skipped rather than aborting the whole run.
    """
    main_tree = None
    report = None
    skipped = []

    for path in nessus_files:
        logger.info("Parsing %s", path)

        try:
            tree = ET.parse(path)
        except ET.ParseError as err:
            logger.warning("Skipping %s: malformed XML (%s)", path, err)
            skipped.append(path)
            continue
        except OSError as err:
            logger.warning("Skipping %s: could not read file (%s)", path, err)
            skipped.append(path)
            continue

        if main_tree is None:
            candidate_report = tree.getroot().find("Report")
            if candidate_report is None:
                logger.warning("Skipping %s: no <Report> element found", path)
                skipped.append(path)
                continue
            main_tree = tree
            report = candidate_report
            report.attrib["name"] = "Merged Report"
            logger.info(" => base report initialized from this file.")
            continue

        this_report = tree.getroot().find("Report")
        if this_report is None:
            logger.warning("Skipping %s: no <Report> element found", path)
            skipped.append(path)
            continue

        for host in this_report.findall(".//ReportHost"):
            existing_host = find_report_host(report, host.attrib.get("name"))
            if existing_host is None:
                logger.info("  adding host: %s", host.attrib.get("name"))
                report.append(host)
                continue

            for item in host.findall("ReportItem"):
                port = item.attrib.get("port")
                plugin_id = item.attrib.get("pluginID")
                if find_report_item(existing_host, port, plugin_id) is None:
                    logger.info("  adding finding: %s:%s", port, plugin_id)
                    existing_host.append(item)

        logger.info(" => done.")

    return main_tree, skipped


def main(argv=None):
    print_banner()

    args = parse_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    target_dir = args.dir
    if not target_dir.is_dir():
        logger.error("Directory not found: %s", target_dir)
        sys.exit(2)

    glob_fn = target_dir.rglob if args.recursive else target_dir.glob
    nessus_files = sorted(glob_fn("*.nessus"))
    if not nessus_files:
        scope = "recursively" if args.recursive else "(non-recursively)"
        logger.error("No .nessus files found in %s %s", target_dir, scope)
        sys.exit(1)

    logger.info("Found %d .nessus file(s) in %s", len(nessus_files), target_dir)

    merged_tree, skipped = merge_nessus_files(nessus_files)

    if merged_tree is None:
        logger.error("No valid .nessus files could be parsed; nothing to write.")
        sys.exit(1)

    output_path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    merged_tree.write(output_path, encoding="utf-8", xml_declaration=True)
    logger.info("Merged report written to %s", output_path)

    if skipped:
        logger.warning(
            "Skipped %d file(s) due to errors: %s",
            len(skipped),
            ", ".join(str(p) for p in skipped),
        )


if __name__ == "__main__":
    main()