#!/usr/bin/env python3
"""Separately labeled follow-up: one prescribed state, no tie for first greedy repair.
Original FEC-R2 implementation is unchanged; this MCP-only harness changes case
selection and sender priorities. It is NOT sent to the RU decoder.
"""
import asyncio, json, sys
from pathlib import Path
import fec_r2 as f

out=Path(sys.argv[1])
f.all_spaces=lambda: [frozenset([0,14])]
weights=iter([4,3,3,3,1])
f.secrets.choice=lambda population: next(weights)
status={'status':'failed'}
try:
    asyncio.run(f.driver(out))
    status={'status':'completed'}
except Exception as e:
    status={'status':'failed','error_type':type(e).__name__}
    print(json.dumps(status),flush=True)
finally:
    f.dump(out/'driver-exit.json',status)
if status['status']!='completed': sys.exit(1)
