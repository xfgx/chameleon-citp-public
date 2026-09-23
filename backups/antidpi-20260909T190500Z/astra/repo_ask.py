#!/usr/bin/env python3
"""Sends a system-prompt file plus a payload file to gpt-6-astra."""
import argparse, io, json, os, sys, urllib.error, urllib.request

DEF_URL = "https://api.experientiallabs.ai/v1/chat/completions"


def api_key():
    key = os.environ.get("EXPLABS_API_KEY")
    if key:
        return key
    for path in ("/files/.env", "./.env"):
        try:
            text = io.open(path, encoding="utf-8").read()
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("EXPLABS_API_KEY="):
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                if value:
                    return value
    sys.exit("ERROR: EXPLABS_API_KEY not found")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--system-file", required=True)
    ap.add_argument("--user-file", required=True)
    ap.add_argument("--prefix", default="")
    ap.add_argument("--model", default="gpt-6-astra")
    ap.add_argument("--url", default=DEF_URL)
    ap.add_argument("--effort", default="high")
    ap.add_argument("--max-output-tokens", type=int, default=24000)
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    system = io.open(args.system_file, encoding="utf-8").read()
    payload = io.open(args.user_file, encoding="utf-8").read()
    if args.prefix:
        payload = args.prefix + "\n" + payload
    body = {
        "model": args.model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": payload}],
        "max_completion_tokens": args.max_output_tokens,
        "reasoning_effort": args.effort,
    }
    req = urllib.request.Request(
        args.url, data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": "Bearer " + api_key(), "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        sys.exit("HTTP %s: %s" % (err.code, err.read().decode("utf-8", "replace")[:900]))
    choice = (data.get("choices") or [{}])[0]
    content = (choice.get("message") or {}).get("content")
    usage = data.get("usage") or {}
    details = usage.get("completion_tokens_details") or {}
    print("STATUS finish_reason=%s" % choice.get("finish_reason"))
    print("USAGE prompt=%s completion=%s total=%s reasoning=%s"
          % (usage.get("prompt_tokens"), usage.get("completion_tokens"),
             usage.get("total_tokens"), details.get("reasoning_tokens")))
    if not content:
        sys.exit("ERROR: empty content (raise --max-output-tokens)")
    print(content.strip())


main()
