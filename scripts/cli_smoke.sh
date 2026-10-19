#!/usr/bin/env bash
# End-to-end smoke test of the zksecuredna CLI: committee setup, record from a
# real receipt, two sealed decryption shares, and opening fields 0 and 1.
# Usage: scripts/cli_smoke.sh <receipt.json>   (see record_fixture RECEIPT_OUT)
set -euo pipefail
RECEIPT=$1
BIN=${BIN:-target/release/zksecuredna}
T=$(mktemp -d)
$BIN committee-deal --threshold 2 --members 3 --out "$T/committee"
CK=$(jq -r .committee_key "$T/committee/committee.json")
$BIN record --receipt "$RECEIPT" --committee-key "$CK" --proof execute \
  --field purpose=smoke-test --field lab_id=lab-001 --field printer_id=p-7 \
  --field location=lab-bench --field timestamp=2026-10-18 --out "$T/submission.json"
# The record id used for decryption shares is the record's statementDigest,
# which the receipt's attestation carries.
RECORD_ID=$(python3 -c 'import json,sys; print(bytes(json.load(open(sys.argv[1]))["attestation"]["attestation"]["statement_digest"]).hex())' "$RECEIPT")
$BIN recipient-keygen --out "$T/recipient.json"
RK=$(jq -r .public_key "$T/recipient.json")
for FIELD in 0 1; do
  EF=$(python3 -c 'import json,sys; print(bytes(json.load(open(sys.argv[1]))["fields"][int(sys.argv[2])]).hex())' "$T/submission.json" "$FIELD")
  S1=$($BIN share --share "$T/committee/share-1.json" --record-id "$RECORD_ID" --field $FIELD --encrypted-field "$EF" --recipient "$RK")
  S3=$($BIN share --share "$T/committee/share-3.json" --record-id "$RECORD_ID" --field $FIELD --encrypted-field "$EF" --recipient "$RK")
  echo "--- field $FIELD opened by authorities 1 and 3:"
  $BIN open --recipient-key "$T/recipient.json" --committee "$T/committee/committee.json" \
    --record-id "$RECORD_ID" --field $FIELD --encrypted-field "$EF" --sealed "$S1" --sealed "$S3"
done
echo "--- one share is not enough:"
if $BIN open --recipient-key "$T/recipient.json" --committee "$T/committee/committee.json" \
    --record-id "$RECORD_ID" --field 1 --encrypted-field "$EF" --sealed "$S1" 2>/dev/null; then
  echo "FAIL: opened with one share"; exit 1
else
  echo "refused, as expected"
fi
