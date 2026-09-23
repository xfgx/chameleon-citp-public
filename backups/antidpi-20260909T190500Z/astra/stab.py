#!/usr/bin/env python3
"""Measure run-to-run stability of TEXTVEC encodings of one identical text.

Reads saved runner outputs, extracts the first @V vector from each, and reports
per-axis spread plus pairwise distance and cosine. All comparisons are done in
integer hundredths for the same reason the runner does: on a 0.05 grid, float
subtraction breaks exact ties.
"""
import math
import re
import sys

V_RE = re.compile(r"@V\s+(\S+)\s*:=\s*\[([^\]]*)\]")
AXES = [
    "valence", "arousal", "dominance", "concreteness",
    "specificity", "formality", "certainty", "temporality",
    "agency", "subjectivity", "complexity", "novelty",
]


def load(path):
    try:
        text = open(path, encoding="utf-8").read().replace("\u2212", "-")
    except OSError as exc:
        print("SKIP %s (%s)" % (path, exc))
        return None
    match = V_RE.search(text)
    if not match:
        print("SKIP %s (no @V block)" % path)
        return None
    try:
        return [int(round(float(x) * 100)) for x in match.group(2).split(",")]
    except ValueError:
        print("SKIP %s (unparsable vector)" % path)
        return None


def dev(units):
    return [(u - 50) / 100.0 for u in units]


def vlen(units):
    return math.sqrt(sum(d * d for d in dev(units)))


def main():
    runs = []
    for path in sys.argv[1:]:
        vec = load(path)
        if vec and len(vec) == 12:
            runs.append(vec)
        elif vec:
            print("SKIP %s (dims=%d)" % (path, len(vec)))
    if len(runs) < 2:
        sys.exit("STABILITY SKIPPED :: need at least two usable runs")

    header = "axis            " + "".join("%8s" % ("run%d" % (i + 1)) for i in range(len(runs)))
    print(header + "  spread  steps")
    worst = 0
    for i, name in enumerate(AXES):
        vals = [r[i] for r in runs]
        spread = max(vals) - min(vals)
        worst = max(worst, spread)
        print("t%02d %-12s" % (i + 1, name)
              + "".join("%8.2f" % (v / 100.0) for v in vals)
              + "    %.2f      %d" % (spread / 100.0, spread // 5))

    print("")
    for a in range(len(runs)):
        for b in range(a + 1, len(runs)):
            va, vb = runs[a], runs[b]
            dist = math.sqrt(sum(((va[i] - vb[i]) / 100.0) ** 2 for i in range(12)))
            da, db = dev(va), dev(vb)
            la, lb = vlen(va), vlen(vb)
            cos = (sum(da[i] * db[i] for i in range(12)) / (la * lb)) if la and lb else float("nan")
            agree = sum(1 for i in range(12) if va[i] == vb[i])
            print("PAIR run%d~run%d distance=%.2f cosine=%.3f identical_axes=%d/12"
                  % (a + 1, b + 1, dist, cos, agree))

    print("")
    print("NORMS " + " ".join("%.2f" % vlen(r) for r in runs))
    flipped = [i + 1 for i in range(12)
               if len({(r[i] > 50) - (r[i] < 50) for r in runs}) > 1]
    if flipped:
        print("SIGN_FLIPS " + " ".join("t%02d" % i for i in flipped))
    else:
        print("SIGN_FLIPS none (every axis kept its direction)")
    print("MAX_AXIS_SPREAD %.2f (%d grid steps)" % (worst / 100.0, worst // 5))


if __name__ == "__main__":
    main()
