#!/bin/bash
cd /files/astra
echo "=== r3-empty START $(date -Iseconds) ==="
python3 astra_textvec.py --mode single --effort medium --allow-empty --text '' > r3-empty.txt 2>&1
echo "=== r3-empty exit=$? ==="
tail -n 8 r3-empty.txt
echo "=== r3-short START $(date -Iseconds) ==="
python3 astra_textvec.py --mode single --effort medium --text-file t-short.txt > r3-short.txt 2>&1
echo "=== r3-short exit=$? ==="
tail -n 14 r3-short.txt
echo "=== R3 DONE $(date -Iseconds) ==="
