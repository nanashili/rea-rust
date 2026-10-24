#!/usr/bin/env python3
"""Alternate fresh release processes, check digests, and record Linux peak RSS."""
import argparse
import csv
import os
import statistics
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("before")
parser.add_argument("after")
parser.add_argument("--rounds", type=int, default=7)
parser.add_argument("--iterations", type=int, default=5)
parser.add_argument("--output", default="performance-results.csv")
parser.add_argument("--workloads", nargs="+", default=["array", "object", "string", "fuses", "plist"])
args = parser.parse_args()
rows = []
for mode in args.workloads:
    digests = set()
    for round_number in range(args.rounds):
        order = (("before", args.before), ("after", args.after))
        if round_number % 2:
            order = order[::-1]
        for version, binary in order:
            with tempfile.TemporaryFile(mode="w+t") as output:
                process = subprocess.Popen([binary, mode, str(args.iterations)], stdout=output)
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                if process.returncode:
                    raise RuntimeError(f"{binary} {mode} exited {process.returncode}")
                output.seek(0)
                _, iterations, milliseconds, digest = output.read().strip("\n").split("\t")
            digests.add(digest)
            rows.append(dict(workload=mode, version=version, round=round_number,
                             iterations=iterations, ms=float(milliseconds),
                             cpu_ms=(usage.ru_utime + usage.ru_stime) * 1000,
                             peak_rss_kib=usage.ru_maxrss, digest=digest))
    assert len(digests) == 1, f"output differs for {mode}: {digests}"
    for version in ("before", "after"):
        group = [row for row in rows if row["workload"] == mode and row["version"] == version]
        print(mode, version, "median ms", statistics.median(row["ms"] for row in group),
              "median peak RSS MiB", statistics.median(row["peak_rss_kib"] for row in group) / 1024,
              flush=True)
with open(args.output, "w", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
