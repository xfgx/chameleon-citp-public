#!/usr/bin/env python3
"""Builds a redacted digest of /files/VPN for gpt-6-astra, plus a TEXTVEC batch."""
import hashlib, io, os, re, sys

ROOT = "/files/VPN"
OUT = "/files/astra/repo-digest.txt"
MAN = "/files/astra/repo-digest-manifest.tsv"
BATCH = "/files/astra/repo-batch.txt"
LABELS = "/files/astra/repo-batch-labels.txt"

SKIP_DIRS = {".git", "node_modules", "android", "dist", ".build", "backups", "data",
             "wintun", "vendor", "__pycache__", ".venv", "testdata", "licenses"}
OK_EXT = {".go", ".md", ".txt", ".sh", ".py", ".yaml", ".yml", ".toml", ".conf",
          ".service", ".mod", ".json", ".c", ".h", ".kt", ".java", ".ps1", ".ini"}
BAD_NAME = re.compile(r"(ssh_ed25519|known_hosts|\.env|secret|\.key$|\.pem$|\.crt$|id_rsa|credential)", re.I)
SECRET = re.compile(r"(BEGIN [A-Z ]*PRIVATE KEY|ssh-ed25519 AAAA|ssh-rsa AAAA|xpl_[0-9a-f]{8}|"
                    r"api[_-]?key\s*[=:]|secret\s*[=:]|password\s*[=:]|passwd\s*[=:]|token\s*[=:]|"
                    r"PresharedKey|PrivateKey\s*=)", re.I)
FILE_CAP = 12000
TOTAL_CAP = 250000
MAX_BYTES = 400000

RANK = [("docs/", 0), ("skills/", 1), ("protocol/", 2), ("cmd/", 3), ("internal/", 4),
        ("mobilecore/", 5), ("packaging/", 7), ("experiments/", 8), ("tools/", 9)]

BATCH_DOCS = ["docs/KS.md", "docs/CHAOSSYNC.md", "docs/CITP-V3-PHANTOM-TTLS.md",
              "docs/ROADMAP-CENSOR-TRANSPORT.md", "docs/CHAOS-METRICS.md",
              "docs/NODE_DEPLOYMENT.md", "docs/KS-RESEARCH.md", "skills/SKILL.md",
              "skills/references/honest-measurement.md", "skills/references/open-fronts.md"]


def rank(rel):
    for prefix, value in RANK:
        if rel.startswith(prefix):
            return value
    return 6


def collect():
    found = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git"))
        for name in sorted(files):
            path = os.path.join(base, name)
            rel = os.path.relpath(path, ROOT)
            if BAD_NAME.search(rel):
                continue
            if os.path.splitext(name)[1].lower() not in OK_EXT:
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size == 0 or size > MAX_BYTES:
                continue
            found.append((rank(rel), rel, path, size))
    found.sort()
    return found


def redact(text):
    out, hits = [], 0
    for line in text.splitlines():
        if SECRET.search(line):
            out.append("[REDACTED-LINE]")
            hits += 1
        else:
            out.append(line)
    return "\n".join(out), hits


def prose(path, limit=900):
    try:
        raw = io.open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
    keep = [ln for ln in raw.splitlines()
            if ln.strip() and not ln.lstrip().startswith(("#", "|", "-", "*", ">", "`"))]
    return redact(" ".join(keep))[0][:limit]


def main():
    files = collect()
    total, redacted, used, blocks = 0, 0, 0, []
    manifest = ["path\tbytes\tsha256_12\tincluded_chars\ttruncated"]
    for _, rel, path, size in files:
        if total >= TOTAL_CAP:
            break
        try:
            raw = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        body, hits = redact(raw)
        redacted += hits
        trunc = len(body) > FILE_CAP
        if trunc:
            body = body[:FILE_CAP] + "\n[TRUNCATED at %d chars of %d]" % (FILE_CAP, len(body))
        room = TOTAL_CAP - total
        if len(body) > room:
            body = body[:room] + "\n[TRUNCATED by total cap]"
            trunc = True
        sha = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]
        blocks.append("===== FILE %s | %d bytes | sha256:%s =====\n%s\n" % (rel, size, sha, body))
        manifest.append("%s\t%d\t%s\t%d\t%s" % (rel, size, sha, len(body), trunc))
        total += len(body)
        used += 1
    header = ("REPO DIGEST /files/VPN\n"
              "files_scanned=%d files_included=%d chars=%d redacted_lines=%d\n"
              "excluded: binaries, android/, dist/, experiments artifacts, backups/, bin/data/, keys, .env\n"
              "each file may be truncated; [REDACTED-LINE] marks removed credential-like lines\n"
              ) % (len(files), used, total, redacted) + "=" * 70 + "\n\n"
    io.open(OUT, "w", encoding="utf-8").write(header + "\n".join(blocks))
    io.open(MAN, "w", encoding="utf-8").write("\n".join(manifest) + "\n")

    chunks, labels = [], []
    for rel in BATCH_DOCS:
        text = prose(os.path.join(ROOT, rel))
        if len(text) < 120:
            continue
        labels.append("b%02d\t%s" % (len(labels) + 1, rel))
        chunks.append(text)
    io.open(BATCH, "w", encoding="utf-8").write("\n---\n".join(chunks) + "\n")
    io.open(LABELS, "w", encoding="utf-8").write("\n".join(labels) + "\n")

    digest = io.open(OUT, encoding="utf-8").read()
    leaks = sum(1 for ln in digest.splitlines() if SECRET.search(ln))
    print("DIGEST files=%d chars=%d est_tokens=%d redacted=%d leaks_after=%d"
          % (used, total, total // 3, redacted, leaks))
    print("BATCH blocks=%d chars=%d" % (len(chunks), sum(len(c) for c in chunks)))
    print("SHA256 %s" % hashlib.sha256(digest.encode("utf-8")).hexdigest()[:24])


main()
