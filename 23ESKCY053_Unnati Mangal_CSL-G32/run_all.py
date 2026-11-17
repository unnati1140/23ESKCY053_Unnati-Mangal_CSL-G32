#!/usr/bin/env python3
"""Reproduce every result of the project with one command.

    python run_all.py

Steps: rebuild the lab captures, run the unit tests, analyse every
scenario, run the evaluation and the threshold study, draw the graphs.
The console output of each step is shown and also saved in results/.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ROOT, "results")


def run(title: str, out_name: str, *args: str) -> bool:
    """Run one step with the current Python; save and show its output."""
    print("\n>>> %s\n    python %s" % (title, " ".join(args)))
    done = subprocess.run([sys.executable] + list(args), cwd=ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    print(done.stdout, end="")
    if out_name:
        with open(os.path.join(RESULTS, out_name), "w", encoding="utf-8") as fh:
            fh.write(done.stdout)
    return done.returncode == 0


def main() -> int:
    os.makedirs(RESULTS, exist_ok=True)
    ok = run("Build the lab captures", "generate_scenarios.txt",
             "lab/generate_scenarios.py")
    ok = run("Unit tests", "unit_tests.txt", "tests/test_detector.py") and ok

    with open(os.path.join(ROOT, "samples", "scenarios.json"),
              encoding="utf-8") as handle:
        runs = json.load(handle)
    for scenario in runs:
        args = ["arp_detector.py", "--read", "samples/" + scenario["file"],
                "--color", "never"]
        name = scenario["file"].replace(".pcap", "")
        if scenario["trusted"]:
            args += ["--trusted", scenario["trusted"]]
            name += "_trusted"
        ok = run("Scenario %s: %s" % (scenario["id"], scenario["title"]),
                 "run_%s.txt" % name, *args) and ok

    ok = run("Evaluation against the ground truth", "evaluation.txt",
             "tests/run_evaluation.py") and ok
    ok = run("Flood threshold study", "threshold_study.txt",
             "tests/threshold_study.py") and ok
    run("Graphs (skipped if matplotlib is missing)", "",
        "tools/plot_results.py")

    print("\n" + "=" * 60)
    print("ALL STEPS PASSED" if ok else "SOME STEPS FAILED - see above")
    print("Outputs are in the results/ folder.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
