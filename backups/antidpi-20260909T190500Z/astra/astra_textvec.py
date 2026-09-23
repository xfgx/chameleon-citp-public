#!/usr/bin/env python3
"""ASTRA TEXTVEC runner: text -> interpretable vector via gpt-6-astra.

Sends astra-textvec.vspace as the system prompt and the target text as the
user message, then independently re-derives every number the model reported:
the vector grid, the @G geometry line (norm / top / neutral_axes) and, in diff
mode, the whole @D block (distance / cosine / max_axis).

The point of the format is that nothing has to be taken on trust: if the model
miscounts, the CHECK lines say so.

All ranking and tie-breaking is done in integer hundredths, never in floats.
On a 0.05 grid, 0.95 and 0.05 are exactly equidistant from neutral, but in
binary floating point |0.95 - 0.5| < |0.05 - 0.5|, which silently reorders a
legitimate tie and produces false mismatches. Integers remove that class of bug.

No temperature / top_p / logprobs are ever sent: gpt-6-astra rejects them.
Stability comes from the 0.05 grid and the self-check rules in the spec.

Reasoning tokens are billed as output tokens and are never returned as text,
so the output budget must leave room for them. If the budget runs out, the
gateway returns finish_reason=length with content=None; that case is reported
explicitly instead of crashing.

Stdlib only, so it runs unchanged inside the MCP container.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "https://api.experientiallabs.ai/v1/chat/completions"
DEFAULT_MODEL = "gpt-6-astra"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SPEC = os.path.join(HERE, "astra-textvec.vspace")
DEFAULT_SCHEMA = os.path.join(HERE, "astra-textvec.schema.json")
ENV_CANDIDATES = ("/files/.env", os.path.join(HERE, ".env"), ".env")

# Reasoning tokens share the output budget, so single-vector work needs a
# generous cap and multi-vector modes need more.
TOKEN_BUDGET = {"single": 6000, "diff": 12000, "batch": 12000}

DIMS = 12
GRID_UNITS = 5      # 0.05 expressed in hundredths
NEUTRAL_UNITS = 50  # 0.50 expressed in hundredths
ROUND_TOL = 0.011   # allows a legitimate last-digit rounding difference
AXES = [
    "valence", "arousal", "dominance", "concreteness",
    "specificity", "formality", "certainty", "temporality",
    "agency", "subjectivity", "complexity", "novelty",
]

V_RE = re.compile(r"@V\s+(\S+)\s*:=\s*\[([^\]]*)\]")
G_RE = re.compile(
    r"@G\s+norm\s*:=\s*([0-9.]+)\s*;\s*top\s*:=\s*([^;\n]*);\s*neutral_axes\s*:=\s*(\d+)")
D_RE = re.compile(
    r"@D\s+distance\s*:=\s*(-?[0-9.]+)\s*;\s*cosine\s*:=\s*(-?[0-9.]+)\s*;"
    r"\s*max_axis\s*:=\s*(t\d{2})\s*\(\s*(-?[0-9.]+)\s*\)")


def normalize(text: str) -> str:
    """Fold the Unicode minus sign used in axis labels down to ASCII."""
    return text.replace("\u2212", "-")


def load_key() -> str:
    key = os.environ.get("EXPLABS_API_KEY", "").strip()
    if key:
        return key
    for path in ENV_CANDIDATES:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("EXPLABS_API_KEY"):
                        _, _, value = line.partition("=")
                        value = value.strip().strip('"').strip("'")
                        if value:
                            return value
        except OSError:
            continue
    sys.exit("ERROR: EXPLABS_API_KEY not found in environment or .env")


def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def post(url: str, key: str, payload: dict, timeout: int) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", "Bearer " + key)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def call(url: str, key: str, payload: dict, timeout: int) -> dict:
    """POST with one graceful retry if the gateway rejects an optional field."""
    try:
        return post(url, key, payload, timeout)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        retryable = ("reasoning_effort", "response_format", "max_completion_tokens")
        dropped = [f for f in retryable if f in payload and f in detail]
        if exc.code == 400 and dropped:
            for field in dropped:
                payload.pop(field, None)
            sys.stderr.write("WARN dropped unsupported field(s): %s\n" % ", ".join(dropped))
            return post(url, key, payload, timeout)
        sys.exit("HTTP %s: %s" % (exc.code, detail))
    except urllib.error.URLError as exc:
        sys.exit("NETWORK ERROR: %s" % exc.reason)


def describe_usage(usage: dict) -> str:
    if not usage:
        return "usage unavailable"
    details = usage.get("completion_tokens_details") or {}
    reasoning = details.get("reasoning_tokens")
    text = "prompt=%s completion=%s total=%s" % (
        usage.get("prompt_tokens"), usage.get("completion_tokens"), usage.get("total_tokens"))
    if reasoning is not None:
        text += " reasoning=%s" % reasoning
    return text


def extract_content(data: dict, budget: int) -> str:
    """Pull message content out of a chat completion, explaining empty results."""
    choices = data.get("choices") or []
    if not choices:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        sys.exit("ERROR: response contained no choices")
    choice = choices[0]
    finish = choice.get("finish_reason")
    content = (choice.get("message") or {}).get("content")
    if content:
        if finish and finish != "stop":
            sys.stderr.write("WARN finish_reason=%s\n" % finish)
        return content
    usage = data.get("usage") or {}
    print("STATUS finish_reason=%s content=empty budget=%d" % (finish, budget))
    print("STATUS %s" % describe_usage(usage))
    if finish == "length":
        sys.exit(
            "ERROR: output budget exhausted before any text was emitted.\n"
            "       Reasoning tokens share the output budget on gpt-6-astra.\n"
            "       Retry with a larger --max-output-tokens or a lower --effort.")
    sys.exit("ERROR: model returned no content (finish_reason=%s)" % finish)


def strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def to_floats(raw: str) -> list:
    values = []
    for item in raw.replace("\n", " ").split(","):
        item = item.strip()
        if item:
            try:
                values.append(float(item))
            except ValueError:
                values.append(float("nan"))
    return values


def parse_blocks(text: str) -> list:
    """Extract each @V vector together with the @G line that belongs to it."""
    text = normalize(text)
    matches = list(V_RE.finditer(text))
    blocks = []
    for pos, match in enumerate(matches):
        end = matches[pos + 1].start() if pos + 1 < len(matches) else len(text)
        segment = text[match.end():end]
        geo = G_RE.search(segment)
        reported = None
        if geo:
            reported = {
                "norm": float(geo.group(1)),
                "top": [t.strip() for t in geo.group(2).split(",") if t.strip()],
                "neutral": int(geo.group(3)),
            }
        blocks.append({"id": match.group(1), "values": to_floats(match.group(2)),
                       "reported": reported})
    return blocks


def to_units(values: list) -> list:
    """Convert grid values to exact integer hundredths."""
    return [int(round(v * 100)) for v in values]


def norm_from_units(dev_units: list) -> float:
    return round(math.sqrt(sum((d / 100.0) ** 2 for d in dev_units)), 2)


def rank_units(magnitudes: list, count: int) -> list:
    """Rank axis indices by magnitude, ties resolved to the lower index."""
    return sorted(range(len(magnitudes)), key=lambda i: (-magnitudes[i], i))[:count]


def geometry(values: list) -> dict:
    dev = [u - NEUTRAL_UNITS for u in to_units(values)]
    magnitudes = [abs(d) for d in dev]
    ranked = rank_units(magnitudes, 3)
    top = ["t%02d%s" % (i + 1, "+" if dev[i] >= 0 else "-") for i in ranked]
    if all(d == 0 for d in dev):
        top = ["NONE"]
    boundary_tie = False
    if len(ranked) == 3:
        cutoff = magnitudes[ranked[-1]]
        boundary_tie = sum(1 for m in magnitudes if m >= cutoff) > 3
    return {
        "norm": norm_from_units(dev),
        "top": top,
        "neutral": sum(1 for d in dev if d == 0),
        "boundary_tie": boundary_tie,
    }


def verify(vec_id: str, values: list, reported=None) -> bool:
    """Re-derive the vector's grid validity and geometry from scratch."""
    problems = []
    if len(values) != DIMS:
        problems.append("dims=%d (expected %d)" % (len(values), DIMS))
    for idx, v in enumerate(values):
        if v != v:
            problems.append("t%02d not numeric" % (idx + 1))
            continue
        if not (0.0 <= v <= 1.0):
            problems.append("t%02d=%s out of range" % (idx + 1, v))
            continue
        hundredths = v * 100
        if abs(hundredths - round(hundredths)) > 1e-6 or int(round(hundredths)) % GRID_UNITS:
            problems.append("t%02d=%s off grid" % (idx + 1, v))
    if problems:
        print("CHECK %s FAIL :: %s" % (vec_id, "; ".join(problems)))
        return False

    geo = geometry(values)
    notes = []
    if reported:
        if abs(reported["norm"] - geo["norm"]) > ROUND_TOL:
            notes.append("NORM MISMATCH reported=%.2f" % reported["norm"])
        if reported["top"] != geo["top"]:
            notes.append("TOP MISMATCH reported=%s" % ",".join(reported["top"]))
        if reported["neutral"] != geo["neutral"]:
            notes.append("NEUTRAL MISMATCH reported=%d" % reported["neutral"])
    else:
        notes.append("no @G line to cross-check")
    if geo["boundary_tie"]:
        notes.append("tie at the top-3 boundary resolved to lowest index")

    verdict = "FAIL" if any("MISMATCH" in n for n in notes) else "OK"
    line = "CHECK %s %s :: dims=12 grid=0.05 norm=%.2f top=%s neutral=%d" % (
        vec_id, verdict, geo["norm"], ",".join(geo["top"]), geo["neutral"])
    if notes:
        line += " | " + "; ".join(notes)
    print(line)
    for idx, v in enumerate(values):
        if abs(int(round(v * 100)) - NEUTRAL_UNITS) >= 25:
            print("       t%02d %-12s %.2f" % (idx + 1, AXES[idx], v))
    return verdict == "OK"


def verify_diff(blocks: list, text: str) -> None:
    """Re-derive the @D block: distance, cosine on deviations, dominant axis."""
    match = D_RE.search(normalize(text))
    if not match:
        print("CHECK-D FAIL :: no @D block found")
        return
    a, b = blocks[0]["values"], blocks[1]["values"]
    if len(a) != DIMS or len(b) != DIMS:
        print("CHECK-D SKIP :: vectors are not both 12-dimensional")
        return

    ua, ub = to_units(a), to_units(b)
    diffs = [ua[i] - ub[i] for i in range(DIMS)]
    distance = round(math.sqrt(sum((d / 100.0) ** 2 for d in diffs)), 2)

    dev_a = [(u - NEUTRAL_UNITS) / 100.0 for u in ua]
    dev_b = [(u - NEUTRAL_UNITS) / 100.0 for u in ub]
    len_a = math.sqrt(sum(d * d for d in dev_a))
    len_b = math.sqrt(sum(d * d for d in dev_b))
    cosine = None
    if len_a > 0 and len_b > 0:
        cosine = round(sum(dev_a[i] * dev_b[i] for i in range(DIMS)) / (len_a * len_b), 2)

    magnitudes = [abs(d) for d in diffs]
    idx = rank_units(magnitudes, 1)[0]
    axis = "t%02d" % (idx + 1)
    spread = magnitudes[idx] / 100.0

    problems = []
    if abs(float(match.group(1)) - distance) > ROUND_TOL:
        problems.append("distance reported=%s computed=%.2f" % (match.group(1), distance))
    if cosine is not None and abs(float(match.group(2)) - cosine) > ROUND_TOL:
        problems.append("cosine reported=%s computed=%.2f" % (match.group(2), cosine))
    if match.group(3) != axis:
        problems.append("max_axis reported=%s computed=%s" % (match.group(3), axis))
    if abs(float(match.group(4)) - spread) > ROUND_TOL:
        problems.append("max_axis spread reported=%s computed=%.2f" % (match.group(4), spread))

    if problems:
        print("CHECK-D FAIL :: %s" % "; ".join(problems))
        return

    ties = [i for i in range(DIMS) if magnitudes[i] == magnitudes[idx]]
    note = ""
    if len(ties) > 1:
        note = " | tie on %s resolved to lowest index" % ",".join(
            "t%02d" % (i + 1) for i in ties)
    print("CHECK-D OK :: distance=%.2f cosine=%s max_axis=%s (%.2f)%s" % (
        distance, "n/a" if cosine is None else "%.2f" % cosine, axis, spread, note))


def main() -> None:
    ap = argparse.ArgumentParser(description="Encode text into a TEXTVEC vector using gpt-6-astra.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", help="Text to encode.")
    src.add_argument("--text-file", help="Read the text to encode from this file.")
    src.add_argument("--stdin", action="store_true", help="Read the text to encode from stdin.")
    ap.add_argument("--mode", choices=["single", "batch", "diff"], default="single")
    ap.add_argument("--spec", default=DEFAULT_SPEC, help="Path to the .vspace file-prompt.")
    ap.add_argument("--schema", default=DEFAULT_SCHEMA, help="Path to the JSON schema.")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], default="high")
    ap.add_argument("--max-output-tokens", type=int, default=None,
                    help="Output budget including reasoning tokens. Defaults by mode.")
    ap.add_argument("--timeout", type=int, default=420)
    ap.add_argument("--json", action="store_true", help="Request structured JSON output.")
    ap.add_argument("--raw", action="store_true", help="Print the full API response.")
    ap.add_argument("--no-verify", action="store_true", help="Skip arithmetic verification.")
    ap.add_argument("--allow-empty", action="store_true",
                    help="Send empty user text to exercise the spec EMPTY_INPUT rule.")
    args = ap.parse_args()

    if args.text is not None:
        payload_text = args.text
    elif args.text_file:
        payload_text = read_file(args.text_file)
    else:
        payload_text = sys.stdin.read()
    payload_text = payload_text.strip()
    if not payload_text and not args.allow_empty:
        sys.exit("ERROR: empty input text (use --allow-empty to test the EMPTY_INPUT rule)")

    budget = args.max_output_tokens or TOKEN_BUDGET[args.mode]
    spec = read_file(args.spec)
    user_message = "#MODE: %s\n%s" % (args.mode, payload_text)

    request = {
        "model": args.model,
        "messages": [
            {"role": "system", "content": spec},
            {"role": "user", "content": user_message},
        ],
        "max_completion_tokens": budget,
        "reasoning_effort": args.effort,
    }
    if args.json:
        schema = json.loads(read_file(args.schema))
        request["response_format"] = {"type": "json_schema", "json_schema": schema}

    key = load_key()
    data = call(args.url, key, request, args.timeout)

    if args.raw:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    content = extract_content(data, budget)
    print(content.strip())

    if args.no_verify:
        return

    print("")
    if args.json:
        try:
            parsed = json.loads(strip_fences(content))
        except json.JSONDecodeError as exc:
            print("CHECK FAIL :: response is not valid JSON (%s)" % exc)
            return
        geo = parsed.get("geometry") or {}
        reported = None
        if "norm" in geo:
            reported = {
                "norm": float(geo.get("norm")),
                "top": [normalize(str(t)).strip() for t in (geo.get("top") or [])],
                "neutral": int(geo.get("neutral_axes", -1)),
            }
        verify(parsed.get("id", "json"), parsed.get("v", []), reported)
    else:
        blocks = parse_blocks(content)
        if not blocks:
            print("CHECK FAIL :: no @V block found in response")
            return
        for block in blocks:
            verify(block["id"], block["values"], block["reported"])
        if args.mode == "diff":
            if len(blocks) == 2:
                verify_diff(blocks, content)
            else:
                print("CHECK-D FAIL :: diff mode expects exactly 2 vectors, got %d"
                      % len(blocks))

    print("USAGE %s" % describe_usage(data.get("usage") or {}))


if __name__ == "__main__":
    main()
