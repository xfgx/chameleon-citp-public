"""Fix an ambiguous output line in stab.py.

The original line was `print("SIGN_AGREEMENT " + " ".join(...) or "...")`, which
always evaluates truthy on the left, so the fallback text never appeared and an
empty list printed a bare label. Replaced with an explicit branch.
"""

path = "/files/astra/stab.py"
source = open(path, encoding="utf-8").read()

old = (
    '    print("SIGN_AGREEMENT " + " ".join(\n'
    '        "t%02d" % (i + 1) for i in range(12)\n'
    '        if len({(r[i] > 50) - (r[i] < 50) for r in runs}) > 1) or "SIGN_AGREEMENT all axes agree")\n'
)
new = (
    "    flipped = [i + 1 for i in range(12)\n"
    "               if len({(r[i] > 50) - (r[i] < 50) for r in runs}) > 1]\n"
    "    if flipped:\n"
    '        print("SIGN_FLIPS " + " ".join("t%02d" % i for i in flipped))\n'
    "    else:\n"
    '        print("SIGN_FLIPS none (every axis kept its direction)")\n'
)

if "SIGN_FLIPS" in source:
    print("PATCH_ALREADY_APPLIED")
else:
    assert source.count(old) == 1, "anchor not unique"
    open(path, "w", encoding="utf-8").write(source.replace(old, new))
    print("PATCH_OK")
