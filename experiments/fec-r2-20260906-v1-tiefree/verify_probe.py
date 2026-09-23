#!/usr/bin/env python3
"""Read-only reconciliation of any saved FEC-R2 trial directory.

Recomputes encodings and recoverable sets from the raw logs with an independent
powerset definition. Performs no transmissions and writes nothing.
"""
import functools, hashlib, itertools, json, sys
from pathlib import Path

K, SIZE, POLICIES = 5, 64, ('certificate', 'greedy', 'recommendation')

def digest(value): return hashlib.sha256(value).hexdigest()

def span(vectors):
    reachable = set()
    for flags in itertools.product((0, 1), repeat=len(vectors)):
        reachable.add(functools.reduce(int.__xor__, [v for f, v in zip(flags, vectors) if f], 0))
    return reachable

def encode(mask, source):
    return bytes(
        functools.reduce(int.__xor__, [source[i][j] for i in range(K) if mask >> i & 1], 0)
        for j in range(SIZE)
    ).hex()

def recoverable(vectors, source):
    reachable = span(vectors)
    return {str(i): digest(source[i]) for i in range(K) if (1 << i) in reachable}

def check(directory):
    p = Path(directory)
    client = [json.loads(line) for line in (p/'mcp-raw.jsonl').read_text().splitlines()]
    server = [json.loads(line) for line in (p/'ru-raw.jsonl').read_text().splitlines()]
    audit = json.loads((p/'audit.json').read_text())
    assert json.loads((p/'driver-exit.json').read_text())['status'] == 'completed'
    assert json.loads((p/'ru-exit.json').read_text())['completed'] is True
    assert audit['core_environment_unchanged'] and audit['listener_closed'] and audit['server_exit'] == 0
    assert audit['raw_mcp_sha256'] == digest((p/'mcp-raw.jsonl').read_bytes())
    assert audit['raw_ru_sha256'] == digest((p/'ru-raw.jsonl').read_bytes())
    opened = {}; repaired = {}; controls = {}; finishes = 0
    for event in server:
        request = event['request']; op = request['op']
        if op == 'open': assert request['case'] not in opened; opened[request['case']] = event
        elif op == 'repair': assert request['case'] not in repaired; repaired[request['case']] = event
        elif op == 'control': assert request['kind'] not in controls; controls[request['kind']] = event
        elif op == 'finish': finishes += 1
        else: raise AssertionError('unexpected operation')
    assert finishes == 1
    sources = []; cases = []; hash_checks = 0; control_checks = 0
    for row in client:
        source = [bytes.fromhex(value) for value in row['sources']]
        assert len(source) == K and all(len(symbol) == SIZE for symbol in source)
        sources.extend(digest(symbol) for symbol in source)
        if 'control' in row:
            event = controls[row['control']]
            assert event['request'] == row['request'] and event['reply'] == row['reply']
            vectors = [mask for mask, payload in row['request']['rows']]
            for mask, payload in row['request']['rows']: assert payload == encode(mask, source)
            expected = recoverable(vectors, source)
            assert expected == event['reply']['decoded']
            control_checks += 1; hash_checks += len(expected)
            continue
        result = row['result']; name = result['case']
        open_event = opened[name]; repair_event = repaired[name]
        assert row['opened'] == open_event['reply'] and row['repair_reply'] == repair_event['reply']
        assert set(open_event['request']) == {'op', 'case', 'rows'}
        vectors = [mask for mask, payload in open_event['request']['rows']]
        assert vectors == result['basis']
        for mask, payload in open_event['request']['rows']: assert payload == encode(mask, source)
        initial = recoverable(vectors, source)
        assert initial == open_event['reply']['initial_decoded']; hash_checks += len(initial)
        for policy in POLICIES:
            repairs = [(mask, payload) for treatment, mask, payload in repair_event['request']['repairs'] if treatment == policy]
            assert len(repairs) == 2
            assert [mask for mask, payload in repairs] == [1 << i for i in result['actions'][policy]]
            for mask, payload in repairs: assert payload == encode(mask, source)
            expected = recoverable(vectors + [mask for mask, payload in repairs], source)
            assert expected == repair_event['reply']['decoded'][policy]; hash_checks += len(expected)
            assert result['scores'][policy] == sum(result['weights'][int(i)] for i in expected)
        assert result['scores']['certificate'] == result['oracle_score']
        assert result['feedback_before_weights']
        cases.append(result)
    ordinary = [r for r in cases if r['case'].startswith('space_')]
    assert len(sources) == len(set(sources)), 'reused source payload inside run'
    return {
        'directory': p.name,
        'verified': True,
        'controls_reconciled': control_checks,
        'cases_reconciled': len(cases),
        'certificate_equals_exhaustive_optimum': len(cases),
        'decoded_hash_checks': hash_checks,
        'fresh_unique_source_symbols': len(sources),
        'strictly_beats_greedy': sum(r['scores']['certificate'] > r['scores']['greedy'] for r in ordinary),
        'strictly_beats_equal_weight_recommendation': sum(r['scores']['certificate'] > r['scores']['recommendation'] for r in ordinary),
        'descriptor_raw_bits_larger_than_dense_basis': sum(r['descriptor_raw_bits_excluding_rank_and_framing'] > r['dense_basis_coefficient_bits_excluding_rank_and_framing'] for r in ordinary),
        'scores_by_case': {r['case']: r['scores'] for r in ordinary} if len(ordinary) <= 3 else 'omitted (sweep)',
    }, set(sources)

if __name__ == '__main__':
    reports = []; payloads = []
    for directory in sys.argv[1:]:
        report, source_set = check(directory); reports.append(report); payloads.append(source_set)
    disjoint = all(not a.intersection(b) for a, b in itertools.combinations(payloads, 2))
    assert disjoint, 'payloads shared between runs'
    print(json.dumps({
        'runs': reports,
        'no_payload_reuse_across_runs': disjoint,
        'method': 'independent powerset recoverability recomputation from raw client and server logs; no new transmissions',
    }, indent=2, sort_keys=True))
