"""Authenticated GitHub Environment review bound to exact Saved Plan and Policy SHA.

A named job containing a SHA is not a cryptographic approval. This guard reads
GitHub's review history and requires the reviewer to explicitly approve a
canonical JSON claim containing the exact immutable Plan, policy and run.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from scripts.day37_fence import Blocked, canonical, current_identity, env, load, require, write

REPO='SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise'
ENVIRONMENTS={'bootstrap':'aws-staging-bootstrap','deploy':'aws-staging-deploy'}
CLAIM_KEYS={'schema','phase','environment','commit','run_id','run_attempt','aws_account_id','plan_sha256','policy_sha256'}


def claim(phase: str, receipt: dict) -> dict:
    require(phase in ENVIRONMENTS, 'unsupported approval phase')
    identity=current_identity()
    for key in ('commit','run_id','run_attempt','aws_account_id'):
        require(str(receipt.get(key))==identity[key], 'approval source differs from reviewed Plan: '+key)
    require(receipt.get('phase')==phase and receipt.get('decision')=='PRIVATE_VERSIONED_PLAN_STORED',
            'only immutable Saved Plan may be approved')
    for key in ('plan_sha256','policy_sha256'):
        value=receipt.get(key)
        require(type(value) is str and len(value)==64 and all(ch in '0123456789abcdef' for ch in value),
                'invalid '+key)
    return {'schema':1,'phase':phase,'environment':ENVIRONMENTS[phase],
            'commit':identity['commit'],'run_id':identity['run_id'],
            'run_attempt':identity['run_attempt'],
            'aws_account_id':identity['aws_account_id'],
            'plan_sha256':receipt['plan_sha256'],'policy_sha256':receipt['policy_sha256']}


def reviews() -> list[dict]:
    require(env('GITHUB_REPOSITORY')==REPO,'wrong GitHub repository')
    run=env('GITHUB_RUN_ID')
    require(run.isdigit(),'invalid GitHub run id')
    token=env('GH_TOKEN')
    url=f'https://api.github.com/repos/{REPO}/actions/runs/{run}/approvals?per_page=100'
    req=Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
                             'X-GitHub-Api-Version':'2022-11-28'})
    with urlopen(req,timeout=15) as response:
        data=json.load(response)
    require(isinstance(data,list) and len(data)<100,'missing or ambiguous paginated approval history')
    return data


def verify(phase: str, receipt: dict, history: list[dict], *, actor: str) -> dict:
    expected=claim(phase,receipt)
    created=datetime.fromisoformat(receipt['created_at'].replace('Z','+00:00'))
    require(created.tzinfo is not None,'Saved Plan timestamp not zone-aware')
    observed=[]
    for row in history:
        if type(row) is not dict:continue
        environments=row.get('environments',[])
        if not isinstance(environments,list) or not any(isinstance(e,dict) and
             e.get('name')==ENVIRONMENTS[phase] for e in environments):
            continue
        # A rejection after approval must block this run, not choose an older approval.
        if str(row.get('state','')).lower()=='rejected':
            raise Blocked('an Environment review rejected this release')
        if str(row.get('state','')).lower()!='approved':continue
        reviewer=row.get('user',{})
        login=reviewer.get('login') if isinstance(reviewer,dict) else None
        require(type(login) is str and bool(login) and login!=actor,
                'approval was not made by an independent reviewer')
        if isinstance(row.get('comment'),str):
            try:
                def unique(pairs):
                    record={}
                    for key,value in pairs:
                        require(key not in record, 'duplicate approval property')
                        record[key]=value
                    return record
                comment=json.loads(row['comment'],object_pairs_hook=unique)
            except json.JSONDecodeError:
                continue
        else:continue
        if not isinstance(comment,dict) or set(comment)!=CLAIM_KEYS or comment!=expected:continue
        instant=datetime.fromisoformat(str(row.get('created_at','')).replace('Z','+00:00'))
        require(instant.tzinfo is not None and instant>=created,'approval occurred before reviewed Plan')
        # Require explicit approval within 4h Plan transport freshness window.
        require((instant-created).total_seconds()<=4*3600,'stale approval')
        observed.append({'reviewer':login,'reviewer_id':reviewer.get('id'),
                         'reviewed_at':instant.isoformat(),
                         'comment_sha256':hashlib.sha256(canonical(comment)).hexdigest()})
    require(len(observed)==1,'exactly one independently authenticated, same-Plan review required')
    return {**expected,**observed[0], 'decision':'EXACT_GITHUB_ENVIRONMENT_PLAN_APPROVED',
            'production_authorized':False,'release_authorized':False}


def final_verify(record: dict, phase: str, receipt: dict, history: list[dict], *, actor: str) -> None:
    fresh=verify(phase,receipt,history,actor=actor)
    require(record==fresh,'approval artifact differs from live GitHub review history')


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('operation',choices=('claim','verify'))
    p.add_argument('--phase',choices=tuple(ENVIRONMENTS),required=True)
    p.add_argument('--receipt',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        rec=load(a.receipt)
        if a.operation=='claim':
            value=claim(a.phase,rec)
        else:
            value=verify(a.phase,rec,reviews(),actor=env('GITHUB_ACTOR'))
        write(a.output,value)
        return 0
    except (Blocked, ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print('BLOCKED: exact approval: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
