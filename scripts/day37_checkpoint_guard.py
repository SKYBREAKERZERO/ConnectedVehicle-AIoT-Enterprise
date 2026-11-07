"""Re-read the live ECS service immediately after ACTIVE Fence, before Apply.

Reject if a human or unrelated actor changed service state between the original
Checkpoint and the Terraform apply. No mutation is performed here.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from scripts.day37_fence import Blocked, env, load, require, write


def equal_original(original: dict, fresh: dict) -> None:
    keys=('commit','run_id','run_attempt','aws_account_id','cluster','service',
          'exists','previous_task_definition','previous_desired_count')
    require(all(original.get(k)==fresh.get(k) for k in keys),
            'ECS pre-Apply Checkpoint changed before Terraform Apply')
    require(original.get('production_authorized') is False and
            original.get('release_authorized') is False,
            'non-Staging Checkpoint')


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--checkpoint',required=True)
    ap.add_argument('--output',required=True)
    a=ap.parse_args()
    try:
        original=load(a.checkpoint)
        from scripts.day37_aws import checkpoint
        latest=checkpoint(env('DAY37_ACCOUNT_ID'),env('DAY37_CLUSTER'),
                          env('DAY37_SERVICE'),Path(a.output).parent/'checkpoint-live.json')
        equal_original(original,latest)
        write(a.output,{'decision':'CHECKPOINT_UNCHANGED_BEFORE_APPLY',
                        'commit':original['commit'],'run_id':original['run_id'],
                        'run_attempt':original['run_attempt'],
                        'production_authorized':False,'release_authorized':False})
        return 0
    except (Blocked,KeyError,TypeError,ValueError,OSError) as error:
        print('BLOCKED: pre-Apply Checkpoint: '+str(error),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
