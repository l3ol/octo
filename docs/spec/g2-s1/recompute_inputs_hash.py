#!/usr/bin/env python3
import json,hashlib,sys,os
p=os.path.join(os.path.dirname(os.path.abspath(__file__)),'PLAN-NODE-OUTPUTS.json')
d=json.load(open(p,encoding='utf-8'));ok=True
for k in ['N1','N2','N3','N4','N5','N8']:
    n=d['nodes'][k];r=hashlib.sha256(json.dumps(n['input'],ensure_ascii=False,separators=(',',':'),sort_keys=True).encode('utf-8')).hexdigest()
    m=r==n['inputs_hash'] and len(r)==64;ok&=m
    print(f"{k} {n['inputs_hash']} {r} {'MATCH' if m else 'MISMATCH'}")
for k in ['N6','N7']:
    n=d['nodes'][k];g=n=={'status':'NOT_RUN_THIS_STAGE','output':None};ok&=g;print(k,'NOT_RUN_THIS_STAGE' if g else 'INVALID')
sys.exit(0 if ok else 1)
