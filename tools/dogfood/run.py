#!/usr/bin/env python3
# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Run the dogfood corpus and print a findings matrix + FP/FN metrics (T-402).

Usage:  python tools/dogfood/run.py [--json report.json]

Exits non-zero if any fixture has a false positive or false negative — a clean
config that isn't silent, or a messy config missing an expected finding. This is
the measurable pre-1.0 gate; the same corpus runs as a CI test.

Drop real (anonymized) configs into ``corpus.py`` to fold them into the run.
"""

from __future__ import annotations

import argparse
import json

from corpus import CHECK_IDS, Result, evaluate_all


def _per_check_metrics(results: list[Result]) -> dict[str, dict[str, int]]:
    """Per-check true/false positive & false negative counts across the corpus."""
    metrics = {cid: {"tp": 0, "fp": 0, "fn": 0} for cid in CHECK_IDS}
    for result in results:
        for cid in CHECK_IDS:
            if cid in result.actual and cid in result.fixture.expects:
                metrics[cid]["tp"] += 1
            elif cid in result.actual:
                metrics[cid]["fp"] += 1
            elif cid in result.fixture.expects:
                metrics[cid]["fn"] += 1
    return metrics


def _ratio(numerator: int, denominator: int) -> str:
    return f"{numerator / denominator:.2f}" if denominator else "n/a"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the mcpscan dogfood corpus.")
    parser.add_argument("--json", metavar="PATH", help="Write the full matrix as JSON.")
    args = parser.parse_args(argv)

    results = evaluate_all()

    print(f"{'fixture':20} {'result':6} expected -> actual")
    print("-" * 72)
    for result in results:
        mark = "PASS" if result.passed else "FAIL"
        exp = ",".join(sorted(result.fixture.expects)) or "(clean)"
        act = ",".join(sorted(result.actual)) or "(clean)"
        print(f"{result.fixture.name:20} {mark:6} {exp} -> {act}")
        if not result.passed:
            if result.false_positives:
                print(f"{'':27}  FALSE POSITIVE: {sorted(result.false_positives)}")
            if result.false_negatives:
                print(f"{'':27}  FALSE NEGATIVE: {sorted(result.false_negatives)}")

    metrics = _per_check_metrics(results)
    print("\nper-check precision / recall")
    print("-" * 72)
    for cid, m in metrics.items():
        precision = _ratio(m["tp"], m["tp"] + m["fp"])
        recall = _ratio(m["tp"], m["tp"] + m["fn"])
        print(f"  {cid:28} tp={m['tp']} fp={m['fp']} fn={m['fn']}  P={precision} R={recall}")

    total_fp = sum(len(r.false_positives) for r in results)
    total_fn = sum(len(r.false_negatives) for r in results)
    passed = sum(1 for r in results if r.passed)
    print(
        f"\n{passed}/{len(results)} fixtures passed; {total_fp} false positive(s), "
        f"{total_fn} false negative(s)"
    )

    if args.json:
        payload = {
            "fixtures": [
                {
                    "name": r.fixture.name,
                    "host": r.fixture.host,
                    "label": r.fixture.label,
                    "expected": sorted(r.fixture.expects),
                    "actual": sorted(r.actual),
                    "false_positives": sorted(r.false_positives),
                    "false_negatives": sorted(r.false_negatives),
                    "passed": r.passed,
                }
                for r in results
            ],
            "metrics": metrics,
            "summary": {"passed": passed, "total": len(results), "fp": total_fp, "fn": total_fn},
        }
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        print(f"wrote {args.json}")

    # Zero-FP on clean + zero-FN on messy is the release gate.
    return 0 if total_fp == 0 and total_fn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
