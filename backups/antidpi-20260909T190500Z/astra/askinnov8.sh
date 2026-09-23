#!/usr/bin/env bash
cd /files/astra
echo "=== START $(date -Is) ==="
python3 repo_ask.py --system-file innov8.prompt --user-file innov8-input.txt --model gpt-6-astra --effort high --max-output-tokens 32000 --timeout 600 > r-innov8.txt 2>&1
echo "EXIT=$? $(date -Is)"
echo "=== DONE $(date -Is) ==="
