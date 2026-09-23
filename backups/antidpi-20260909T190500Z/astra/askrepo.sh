#!/bin/bash
cd /files/astra
echo "=== START $(date -Iseconds) ==="
python3 astra_textvec.py --mode batch --effort high --text-file repo-batch.txt --max-output-tokens 32000 > r-repo-batch.txt 2>&1 &
A=$!
python3 repo_ask.py --system-file repo-review.prompt --user-file repo-digest.txt --effort high --max-output-tokens 32000 > r-repo-review.txt 2>&1 &
B=$!
wait $A; echo "=== A textvec exit=$? $(date -Iseconds) ==="
wait $B; echo "=== B review exit=$? $(date -Iseconds) ==="
wc -c r-repo-batch.txt r-repo-review.txt
echo "=== REPO DONE $(date -Iseconds) ==="
