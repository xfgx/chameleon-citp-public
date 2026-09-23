"""Allow an empty user text so the spec's EMPTY_INPUT rule becomes testable."""

path = "/files/astra/astra_textvec.py"
source = open(path, encoding="utf-8").read()

old_arg = '    ap.add_argument("--no-verify", action="store_true", help="Skip arithmetic verification.")\n'
new_arg = old_arg + (
    '    ap.add_argument("--allow-empty", action="store_true",\n'
    '                    help="Send empty user text to exercise the spec EMPTY_INPUT rule.")\n'
)

old_guard = (
    "    payload_text = payload_text.strip()\n"
    "    if not payload_text:\n"
    '        sys.exit("ERROR: empty input text")\n'
)
new_guard = (
    "    payload_text = payload_text.strip()\n"
    "    if not payload_text and not args.allow_empty:\n"
    '        sys.exit("ERROR: empty input text (use --allow-empty to test the EMPTY_INPUT rule)")\n'
)

if "--allow-empty" in source:
    print("PATCH_ALREADY_APPLIED")
else:
    assert source.count(old_arg) == 1, "argparse anchor not unique"
    assert source.count(old_guard) == 1, "guard anchor not unique"
    source = source.replace(old_arg, new_arg).replace(old_guard, new_guard)
    open(path, "w", encoding="utf-8").write(source)
    print("PATCH_OK")
