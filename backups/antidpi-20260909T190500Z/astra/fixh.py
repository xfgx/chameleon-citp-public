import io
P="/files/astra/mkdigest.py"
t=io.open(P,encoding="utf-8").read()
old='"=" * 70 + "\\n\\n") % (len(files), used, total, redacted)'
new=') % (len(files), used, total, redacted) + "=" * 70 + "\\n\\n"'
print("HITS", t.count(old))
t=t.replace(old,new,1)
io.open(P,"w",encoding="utf-8").write(t)
print("FIXED")
