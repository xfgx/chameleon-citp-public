#!/usr/bin/env bash
set -euo pipefail

: "${FUZZ_TIME:=30s}"
python3 -m py_compile protocol/reference_parser.py
python3 protocol/reference_parser.py

go test ./internal/chameleon
go test -race ./internal/chameleon
for target in \
  FuzzDecodeCITPObject \
  FuzzDecodeResolutionObject \
  FuzzDecodeMigrationTicket \
  FuzzParseTarget \
  FuzzParseKeys \
  FuzzReadTransportFrame \
  FuzzServerHandshakeParser
do
  go test ./internal/chameleon -run '^$' -fuzz "^${target}$" -fuzztime "$FUZZ_TIME"
done

go test ./mobilecore -run '^$' -fuzz '^FuzzReadSocksAddr$' -fuzztime "$FUZZ_TIME"
