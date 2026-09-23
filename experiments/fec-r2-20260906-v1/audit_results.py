#!/usr/bin/env python3
"""Read-only verification of saved live trials; no new traffic or simulation."""
import collections, hashlib, itertools, json, sys
from pathlib import Path

def digest(b): return hashlib.sha256(b).hexdigest()
def linear_span(vectors):
    # Independent powerset definition; do not import the experiment program.
    result = set()
    for flags in itertools.product((0, 1), repeat=len(vectors)):
        value = 0
        for flag, vector in zip(flags, vectors):
            if flag: value ^= vector
        result.add(value)
    return result

def encode(mask, source):
    return bytes([__import__('functools').reduce(int.__xor__, [source[i][j] for i in range(5) if mask & (1 << i)], 0) for j in range(64)]).hex()

def verify(directory):
    p = Path(directory)
    client = [json.loads(line) for line in (p/'mcp-raw.jsonl').read_text().splitlines()]
    server = [json.loads(line) for line in (p/'ru-raw.jsonl').read_text().splitlines()]
    summary = json.loads((p/'summary.json').read_text())
    audit = json.loads((p/'audit.json').read_text())
    assert json.loads((p/'driver-exit.json').read_text())['status'] == 'completed'
    assert json.loads((p/'ru-exit.json').read_text())['completed'] is True
    assert audit['core_environment_unchanged'] and audit['listener_closed']
    assert audit['raw_mcp_sha256'] == digest((p/'mcp-raw.jsonl').read_bytes())
    assert audit['raw_ru_sha256'] == digest((p/'ru-raw.jsonl').read_bytes())
    events = {}; controls = {}; observed = collections.Counter()
    for event in server:
        request = event['request']; op = request['op']; observed[op] += 1
        if op in ('open','repair'):
            key = (request['case'], op)
            assert key not in events; events[key] = event
        if op == 'control':
            assert request['kind'] not in controls; controls[request['kind']] = event
    all_sources = []; states = set(); ranks = collections.Counter(); cases=[]; descriptor_states={}; rankless_states={}
    decoded_hash_checks = 0
    for row in client:
        source = [bytes.fromhex(s) for s in row['sources']]
        assert len(source)==5 and all(len(s)==64 for s in source)
        all_sources.extend(digest(s) for s in source)
        if 'control' in row:
            event=controls[row['control']]
            assert event['request']==row['request'] and event['reply']==row['reply']
            vectors=[item[0] for item in row['request']['rows']]
            for mask, payload in row['request']['rows']: assert payload==encode(mask,source)
            recovered={str(i):digest(source[i]) for i in range(5) if 1<<i in linear_span(vectors)}
            assert recovered==event['reply']['decoded']; decoded_hash_checks+=len(recovered)
            continue
        r=row['result']; name=r['case']; opened=events[(name,'open')]; repaired=events[(name,'repair')]
        assert row['opened']==opened['reply'] and row['repair_reply']==repaired['reply']
        assert set(opened['request'])=={'op','case','rows'}
        coefficients=[mask for mask,payload in opened['request']['rows']]
        assert coefficients==r['basis']
        for mask,payload in opened['request']['rows']: assert payload==encode(mask,source)
        initial={str(i):digest(source[i]) for i in range(5) if 1<<i in linear_span(coefficients)}
        assert initial==opened['reply']['initial_decoded']; decoded_hash_checks+=len(initial)
        for policy in ('certificate','greedy','recommendation'):
            repairs=[(m,x) for treatment,m,x in repaired['request']['repairs'] if treatment==policy]
            assert len(repairs)==2
            assert [m for m,x in repairs]==[1<<i for i in r['actions'][policy]]
            for mask,payload in repairs: assert payload==encode(mask,source)
            known=linear_span(coefficients+[m for m,x in repairs])
            expected={str(i):digest(source[i]) for i in range(5) if 1<<i in known}
            assert expected==repaired['reply']['decoded'][policy]
            decoded_hash_checks+=len(expected)
            assert r['scores'][policy]==sum(r['weights'][int(i)] for i in expected)
        assert r['scores']['certificate']==r['oracle_score'] and r['feedback_before_weights']
        if name.startswith('space_'):
            space=tuple(sorted(linear_span(coefficients)))
            assert space not in states; states.add(space); ranks[len(coefficients)]+=1; cases.append(r)
            signature=json.dumps(r['certificate'],sort_keys=True)
            rankless=json.dumps({k:v for k,v in r['certificate'].items() if k!='rank'},sort_keys=True)
            descriptor_states.setdefault(signature,[]).append(name); rankless_states.setdefault(rankless,[]).append(name)
    assert len(all_sources)==len(set(all_sources)), 'reused source payload detected'
    assert observed=={'control':4,'open':376,'repair':376,'finish':1}
    assert len(client)==380 and len(server)==757 and len(states)==374
    assert dict(ranks)=={0:1,1:31,2:155,3:155,4:31,5:1}
    greedy_better=[r for r in cases if r['scores']['certificate']>r['scores']['greedy']]
    recommendation_better=[r for r in cases if r['scores']['certificate']>r['scores']['recommendation']]
    smaller=[r for r in cases if r['descriptor_raw_bits_excluding_rank_and_framing']<r['dense_basis_coefficient_bits_excluding_rank_and_framing']]
    larger=[r for r in cases if r['descriptor_raw_bits_excluding_rank_and_framing']>r['dense_basis_coefficient_bits_excluding_rank_and_framing']]
    assert len(greedy_better)==summary['certificate_beats_greedy_states']
    assert len(recommendation_better)==summary['certificate_beats_old_recommendation_states']
    assert len(smaller)==summary['descriptor_smaller_than_dense_basis_states']
    assert len(larger)==summary['descriptor_larger_than_dense_basis_states']
    jbytes=[r['certificate_json_bytes'] for r in cases]
    result={'directory':str(p),'verified':True,'client_records':len(client),'server_records':len(server),'unique_states':len(states),'rank_distribution':dict(ranks),'fresh_unique_source_symbols':len(all_sources),'decoded_hash_checks':decoded_hash_checks,'certificate_optimum_matches_including_two_witnesses':len(cases)+2,'strictly_beats_greedy':len(greedy_better),'strictly_beats_old_recommendation':len(recommendation_better),'descriptor_raw_bits_smaller_equal_larger':[len(smaller),len(cases)-len(smaller)-len(larger)],'certificate_json_bytes_min_max':[min(jbytes),max(jbytes)],'distinct_ranked_descriptors':len(descriptor_states),'distinct_rankless_descriptors':len(rankless_states),'representative_greedy_difference':greedy_better[0] if greedy_better else None,'state_snapshot_unchanged':True,'listener_closed':True,'mcp_raw_sha256':audit['raw_mcp_sha256'],'ru_raw_sha256':audit['raw_ru_sha256']}
    return result,set(all_sources)

if __name__=='__main__':
    results=[]; source_sets=[]
    for directory in sys.argv[1:]:
        result,sources=verify(directory); results.append(result); source_sets.append(sources)
    independent_payloads=all(not a.intersection(b) for a,b in itertools.combinations(source_sets,2))
    assert independent_payloads
    output={'runs':results,'no_payload_reuse_across_runs':independent_payloads,'method':'independent raw client/server reconciliation and powerset recoverability check; no new transmissions'}
    print(json.dumps(output,indent=2,sort_keys=True))
