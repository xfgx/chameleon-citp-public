#!/usr/bin/env python3
"""Turns TEXTVEC batch output over repo docs into a labelled geometry map."""
import io, math, re, sys

AXES = ["valence", "arousal", "dominance", "concreteness", "specificity", "formality",
        "certainty", "temporality", "agency", "subjectivity", "complexity", "novelty"]
V_RE = re.compile(r"@V\s+(\S+)\s*:=\s*\[([^\]]*)\]")

out = sys.argv[1] if len(sys.argv) > 1 else "/files/astra/r-repo-batch.txt"
lab = sys.argv[2] if len(sys.argv) > 2 else "/files/astra/repo-batch-labels.txt"

labels = {}
for line in io.open(lab, encoding="utf-8"):
    if "\t" in line:
        key, path = line.rstrip("\n").split("\t", 1)
        labels[key] = path

vecs = []
for vid, body in V_RE.findall(io.open(out, encoding="utf-8").read()):
    units = [int(round(float(x) * 100)) for x in body.replace("\u2212", "-").split(",")]
    if len(units) == 12:
        vecs.append((vid, labels.get(vid, vid), units))

if len(vecs) < 2:
    sys.exit("NO_VECTORS parsed=%d" % len(vecs))


def dev(units):
    return [u - 50 for u in units]


def dist(a, b):
    return math.sqrt(sum(((x - y) / 100.0) ** 2 for x, y in zip(a, b)))


def cos(a, b):
    da, db = dev(a), dev(b)
    na = math.sqrt(sum(x * x for x in da))
    nb = math.sqrt(sum(x * x for x in db))
    if na == 0 or nb == 0:
        return None
    return sum(x * y for x, y in zip(da, db)) / (na * nb)


print("DOCS %d" % len(vecs))
print("%-4s %-46s %6s %s" % ("id", "file", "norm", "top3"))
for vid, path, units in vecs:
    d = dev(units)
    order = sorted(range(12), key=lambda i: (-abs(d[i]), i))[:3]
    top = ",".join("t%02d%s" % (i + 1, "+" if d[i] >= 0 else "-") for i in order)
    print("%-4s %-46s %6.2f %s" % (vid, path, math.sqrt(sum((x / 100.0) ** 2 for x in d)), top))

print("\nDISTANCE MATRIX (euclidean, 12D)")
print("     " + " ".join("%5s" % v[0] for v in vecs))
for vid, _, units in vecs:
    row = " ".join("%5.2f" % dist(units, other) for _, _, other in vecs)
    print("%-4s %s" % (vid, row))

pairs = []
for i in range(len(vecs)):
    for j in range(i + 1, len(vecs)):
        pairs.append((dist(vecs[i][2], vecs[j][2]), cos(vecs[i][2], vecs[j][2]),
                      vecs[i][0], vecs[j][0]))
pairs.sort()
print("\nCLOSEST PAIRS")
for d, c, a, b in pairs[:4]:
    print("  %s ~ %s  distance=%.2f cosine=%s" % (a, b, d, "n/a" if c is None else "%.3f" % c))
print("FARTHEST PAIRS")
for d, c, a, b in pairs[-4:][::-1]:
    print("  %s ~ %s  distance=%.2f cosine=%s" % (a, b, d, "n/a" if c is None else "%.3f" % c))

print("\nAXIS PROFILE ACROSS DOCS")
print("%-14s %5s %5s %5s %6s" % ("axis", "min", "mean", "max", "spread"))
for i, name in enumerate(AXES):
    col = [v[2][i] / 100.0 for v in vecs]
    print("%-14s %5.2f %5.2f %5.2f %6.2f"
          % ("t%02d %s" % (i + 1, name), min(col), sum(col) / len(col), max(col),
             max(col) - min(col)))

centroid = [sum(v[2][i] for v in vecs) / float(len(vecs)) for i in range(12)]
print("\nDISTANCE TO CENTROID (higher = more atypical doc)")
for vid, path, units in sorted(vecs, key=lambda v: -dist(v[2], centroid)):
    print("  %-4s %-46s %.2f" % (vid, path, dist(units, centroid)))
