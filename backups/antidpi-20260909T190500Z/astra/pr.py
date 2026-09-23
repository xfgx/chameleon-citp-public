import io
P="/files/astra/astra_textvec.py"
t=io.open(P,encoding="utf-8").read()
old='    top = ["t%02d%s" % (i + 1, "+" if dev[i] >= 0 else "-") for i in ranked]\n    boundary_tie = False\n'
new='    top = ["t%02d%s" % (i + 1, "+" if dev[i] >= 0 else "-") for i in ranked]\n    if all(d == 0 for d in dev):\n        top = ["NONE"]\n    boundary_tie = False\n'
if new in t:
    print("ALREADY")
elif t.count(old)==1:
    io.open(P,"w",encoding="utf-8").write(t.replace(old,new,1))
    print("RUNNER_PATCH_OK")
else:
    print("RUNNER_PATCH_FAIL hits=%d"%t.count(old))
