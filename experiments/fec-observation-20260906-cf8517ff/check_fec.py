"""Offline FEC observation calibration. No sockets, VPN changes, or external targets."""
import argparse
from collections import defaultdict
import hashlib
from itertools import permutations
import json
from pathlib import Path
import platform

COEFFICIENTS = (1, 2, 4, 8, 16, 3, 30)
LABELS = ('S0', 'S1', 'S2', 'S3', 'S4', 'P01', 'P1234')
K = 5
DEADLINE = 4

def row_span(rows):
    values = {0}
    for row in rows:
        values |= {value ^ row for value in values}
    return values

def gaussian_rank(rows):
    pivots = {}
    for row in rows:
        value = row
        while value:
            bit = value.bit_length() - 1
            if bit in pivots:
                value ^= pivots[bit]
            else:
                pivots[bit] = value
                break
    return len(pivots)

def gaussian_decodable(rows):
    rank = gaussian_rank(rows)
    return [j for j in range(K) if gaussian_rank(list(rows) + [1 << j]) == rank]

def truth_table_decodable(rows):
    buckets = defaultdict(list)
    for message in range(1 << K):
        observed = tuple((row & message).bit_count() % 2 for row in rows)
        buckets[observed].append(message)
    return [j for j in range(K)
            if all(len({(message >> j) & 1 for message in possible}) == 1
                   for possible in buckets.values())]

def inversion_count(order):
    return sum(order[i] > order[j] for i in range(len(order))
               for j in range(i + 1, len(order)))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    raw_path = out / 'raw.jsonl'
    count = 0
    completion_controls = 0
    order_invariance_controls = 0
    with raw_path.open('x', encoding='utf-8') as raw:
        for order in permutations(range(len(COEFFICIENTS))):
            received = [COEFFICIENTS[i] for i in order[:DEADLINE]]
            span = row_span(received)
            decoded = [j for j in range(K) if (1 << j) in span]
            rank = len(span).bit_length() - 1
            assert rank == gaussian_rank(received)
            assert decoded == gaussian_decodable(received)
            assert row_span(sorted(received)) == span
            order_invariance_controls += 1
            full = [COEFFICIENTS[i] for i in order]
            assert gaussian_decodable(full) == list(range(K))
            completion_controls += 1
            row = {'order': list(order), 'inversions': inversion_count(order),
                   'systematic_before_deadline': sum(i < K for i in order[:DEADLINE]),
                   'rank_before_deadline': rank, 'decoded_sources': decoded,
                   'recoverable_count': len(decoded), 'eventual_loss': 0}
            raw.write(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n')
            count += 1
    assert count == 5040
    # Re-read saved records and rederive the headline through Gaussian elimination.
    groups = defaultdict(list)
    seen = set()
    reread = 0
    with raw_path.open(encoding='utf-8') as raw:
        for line in raw:
            row = json.loads(line)
            order = tuple(row['order'])
            assert order not in seen and sorted(order) == list(range(7))
            seen.add(order)
            received = [COEFFICIENTS[i] for i in order[:DEADLINE]]
            assert gaussian_decodable(received) == row['decoded_sources']
            key = (row['inversions'], row['systematic_before_deadline'], row['rank_before_deadline'])
            groups[key].append(row)
            reread += 1
    assert reread == count
    witness = None
    for key in sorted(groups):
        rows = sorted(groups[key], key=lambda row: row['order'])
        for left_index, left in enumerate(rows):
            right = next((r for r in rows[left_index + 1:]
                          if r['recoverable_count'] != left['recoverable_count']), None)
            if right is not None:
                witness = {'matched_key': {'inversions': key[0], 'systematic_before_deadline': key[1],
                                           'rank_before_deadline': key[2]},
                           'left': left, 'right': right}
                break
        if witness is not None:
            break
    if witness is not None:
        for name in ('left', 'right'):
            row = witness[name]
            rows = [COEFFICIENTS[i] for i in row['order'][:DEADLINE]]
            assert truth_table_decodable(rows) == row['decoded_sources']
            row['arrival_labels'] = [LABELS[i] for i in row['order']]
        witness['truth_table_confirmation'] = True
        witness['completion_decodable_both'] = list(range(K))
    positive = gaussian_decodable(COEFFICIENTS[:K])
    assert positive == list(range(K))
    summary = {
        'scope': 'exact finite abstract code calibration; not a VPN or network benchmark',
        'python': platform.python_version(), 'implementation': platform.python_implementation(),
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'code_coefficients': list(COEFFICIENTS), 'labels': list(LABELS),
        'source_symbols': K, 'transmitted_symbols': len(COEFFICIENTS), 'deadline_arrival_count': DEADLINE,
        'cases': count, 'saved_records_rechecked': reread,
        'completion_controls_passed': completion_controls,
        'same_set_order_invariance_controls_passed': order_invariance_controls,
        'positive_control_decoded': positive,
        'counterexample_found': witness is not None, 'witness': witness,
        'raw_sha256': hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        'statistical_interpretation': 'none; complete finite permutation space, not traffic probabilities',
        'novelty': 'calibration of known partial-decoding principles; novelty not claimed',
        'all_checks_passed': True}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary, sort_keys=True))

if __name__ == '__main__':
    main()
