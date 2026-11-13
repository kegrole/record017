"""Command line entry: python -m keyaudit.cli --dir <dir> --out <report>."""

import argparse
import sys

from . import report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="keyaudit",
        description="Audit RSA keys and X.509 certificates (stdlib only).",
    )
    parser.add_argument("--dir", required=True,
                        help="directory to scan recursively for PEM files")
    parser.add_argument("--out", required=True,
                        help="path of the JSON report to write")
    return parser


def main(argv=None, stream=None):
    args = build_parser().parse_args(argv)
    stream = stream if stream is not None else sys.stdout
    records = report.audit_directory(args.dir)
    payload = report.write_report(records, args.out)
    summary = payload["summary"]
    print(
        "summary: files=%(files)d private_keys=%(private_keys)d "
        "public_keys=%(public_keys)d certificates=%(certificates)d "
        "issues=%(issues)d" % summary,
        file=stream,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
