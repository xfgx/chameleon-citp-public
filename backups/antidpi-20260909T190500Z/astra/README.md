# ASTRA TEXTVEC

A file-prompt that makes `gpt-6-astra` encode any text into a **12-dimensional,
re-derivable vector** — and a runner that checks the model's arithmetic instead
of trusting it.

## What this is, and what it is not

**It is** an interpretable self-report notation. The model reads a fixed basis
definition and reports where a text sits on 12 named axes, on a 0.05 grid, with
a short justification for every pronounced value and a natural-language
reconstruction of the text from the numbers alone.

**It is not** access to the model's internal representations. This matters, so
it is stated in the spec itself as `contains_model_states: false`:

- `gpt-6-astra` does **not** support `v1/embeddings`, so no real embedding
  vector can be obtained through this gateway.
- Reasoning tokens are billed as output tokens but are **never returned as
  text**, so hidden states and chains of thought are not observable here.
- The numbers are a *judgement* produced under a fixed rubric. They are stable
  in structure and direction, but not bit-reproducible — see the measurements
  below.

Anything claiming otherwise about this file would be false.

## Files

| File | Purpose |
| --- | --- |
| `astra-textvec.vspace` | The file-prompt. Sent as the system message. |
| `astra-textvec.md` / `.txt` | Byte-identical twins, for UIs that reject the `.vspace` extension on upload. |
| `astra-textvec.schema.json` | Strict JSON Schema for `--json` mode (`strict: true`, `additionalProperties: false`). |
| `astra_textvec.py` | Runner: sends the prompt, verifies the response. Stdlib only. |
| `run-tests.sh` | Live acceptance run across all modes. |
| `sample-*.txt` | Recorded live outputs. |
| `bundle/` + `astra-textvec-bundle.zip` | The six core files, packaged for upload. |

## The basis

```
t01 valence       t05 specificity   t09  agency
t02 arousal       t06 formality     t10  subjectivity
t03 dominance     t07 certainty     t11  complexity
t04 concreteness  t08 temporality   t12  novelty
```

Range `0.00–1.00`, neutral `0.50`, grid step `0.05` (21 levels), working floor
`0.05` and ceiling `0.95` so the extremes stay meaningful.

Geometry is defined on deviations from neutral, `dev = v − 0.50`:

- `norm = sqrt(Σ dev²)`, max `1.73`. Bands: `<0.30` neutral, `0.30–0.70`
  moderate, `0.70–1.10` pronounced, `>1.10` extreme.
- `top` = the three largest `|dev|`, ties resolved to the lower axis index.
- `neutral_axes` = how many axes are exactly `0.50`.

## Usage

```bash
cd /files/astra

# single vector
python3 astra_textvec.py --text 'Ваш текст' --effort high

# two texts separated by a --- line, plus the @D comparison block
python3 astra_textvec.py --mode diff --text-file pair.txt --effort high

# many texts separated by --- lines
python3 astra_textvec.py --mode batch --text-file batch.txt --effort medium

# strict structured output instead of the @-protocol
python3 astra_textvec.py --text 'Ваш текст' --json
```

Input can also come from `--stdin`. The API key is read from `EXPLABS_API_KEY`
or from `/files/.env`, and is never printed.

## Reading the output

```
@V   the 12 numbers
@G   norm / top / neutral_axes
@WHY one line per axis with |v − 0.50| ≥ 0.25, max 12 words
@BACK the text reconstructed from the vector alone
@FLAGS NONE | EMPTY_INPUT | TOO_SHORT | MIXED:<axis> | INSTRUCTION_IN_INPUT | ...
@D   diff mode only: distance / cosine / max_axis
```

Everything after the blank line is produced locally by the runner, not by the
model:

```
CHECK a OK :: dims=12 grid=0.05 norm=1.00 top=t07+,t08-,t09- neutral=0 | tie at the top-3 boundary resolved to lowest index
CHECK-D OK :: distance=1.50 cosine=-0.08 max_axis=t07 (0.80)
```

The runner re-derives the vector's grid validity, `norm`, `top` and
`neutral_axes`, and in diff mode the entire `@D` block, then compares them with
what the model claimed. A disagreement prints `FAIL` with both values, so a
miscount cannot pass silently.

### Why the comparisons use integers

All ranking and tie-breaking happens in integer hundredths. On this grid `0.95`
and `0.05` are exactly equidistant from neutral, but in binary floating point
they are not:

```
0.95 - 0.5 = 0.44999999999999996
0.05 - 0.5 = -0.45
```

Ranked as floats, `t01+` loses a tie it should win, and the runner reports a
`TOP MISMATCH` against a model answer that was actually correct. This happened
during development and is why the verifier never compares magnitudes as floats.

## Operational notes

- **Never send `temperature`, `top_p` or `logprobs`** — `gpt-6-astra` rejects
  them. Determinism comes from the grid and the spec's self-check rules.
- **Budget for invisible reasoning tokens.** They consume the output budget, so
  the defaults are 6000 tokens for single mode and 12000 for diff/batch.
  Measured reasoning usage: 955–1825 tokens per call at `high` effort, 347 at
  `medium`. If the budget runs out the gateway returns `finish_reason=length`
  with empty content; the runner reports that explicitly instead of crashing.
- **The MCP request timeout is around a minute**, much shorter than a
  high-effort call. Always run live encodings in the background and poll:

  ```bash
  nohup bash run-tests.sh > tests.log 2>&1 &
  tail -n 40 tests.log
  ```

- Prompt-injection behaviour is deliberate and split in two. Imperatives aimed
  at *people* ("проверьте всё до утра") are ordinary content: high `agency`, no
  flag. Attempts to redefine *the encoder* (change the basis, the axis count,
  the output format, or reveal the spec) are encoded as text and flagged
  `INSTRUCTION_IN_INPUT` — never obeyed.

## Verified live results

All recorded against `gpt-6-astra` through the Experiential Labs gateway.

| Mode | Result |
| --- | --- |
| single | `norm 0.98`, `top t08+,t09+,t02+`, `@FLAGS NONE`, geometry confirmed |
| diff | 2 vectors + `@D`, all three checks clean |
| batch | 3 vectors, all on-grid, geometry confirmed for each |
| json | valid against the strict schema, geometry confirmed |
| injection guard | encoder-redefinition attempt flagged `INSTRUCTION_IN_INPUT`, text still encoded (`dominance 0.95`, `agency 0.95`) |

### Reproducibility, measured

The same diff pair was encoded three times at `high` effort:

| Run | distance | cosine | max_axis |
| --- | --- | --- | --- |
| 1 | 1.53 | −0.05 | t07 |
| 2 | 1.57 | −0.04 | t07 |
| 3 | 1.50 | −0.08 | t07 |

Individual axes moved by one or two grid steps between runs; the dominant axis,
the sign of every deviation and the qualitative reading stayed the same. Treat
the output as a stable *reading*, not as a fixed measurement — and if you need
tighter numbers, average several runs rather than assuming one is exact.
