#!/usr/bin/env bash
# Fresh live acceptance run: a new text, a 3x stability probe, and the four
# @FLAGS paths that were never exercised against the API before.
cd /files/astra || exit 1

run_case() {
  name="$1"
  shift
  echo "=== $name START $(date -Is) ==="
  python3 astra_textvec.py "$@" > "r-$name.txt" 2>&1
  rc=$?
  echo "=== $name exit=$rc $(date -Is) ==="
  tail -n 12 "r-$name.txt"
  echo ""
}

# Same fresh text three times, to measure run-to-run spread.
run_case sci-1 --mode single --effort high --text-file t-sci.txt
run_case sci-2 --mode single --effort high --text-file t-sci.txt
run_case sci-3 --mode single --effort high --text-file t-sci.txt

# Flag paths never tested live until now.
run_case empty --mode single --effort medium --allow-empty --text ''
run_case short --mode single --effort medium --text-file t-short.txt
run_case code  --mode single --effort medium --text-file t-code.txt
run_case mixed --mode single --effort medium --text-file t-mixed.txt

echo "=== STABILITY ==="
python3 stab.py r-sci-1.txt r-sci-2.txt r-sci-3.txt
echo "=== ALL DONE $(date -Is) ==="
