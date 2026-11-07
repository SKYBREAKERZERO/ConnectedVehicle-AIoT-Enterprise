"""Independent manual reconciliation proof; never auto-repair or roll back a schema.

Execute only in protected Day37 recovery environment, after Cosign verification
and a Terraform -detailed-exitcode 0, with externally approved restored digest.
"""
from __future__ import annotations
import argparse
import os
import sys
import subprocess
from scripts.day37_fence import Blocked, DIGEST, current_identity, env, load, require, write
from scripts.day37_reconcile import zero_drift


def build(fence: dict, plan: dict, live: dict, exit_code: int, digest: str) -> dict:
    current = current_identity()
    require(fence.get('schema') == 2 and fence.get('state') == 'ACTIVE' and
            fence.get('phase') == 'deploy', 'manual ECS rollback may only close deploy fence')
    require(fence.get('aws_account_id') == current['aws_account_id'] and fence.get('repository') == current['repository'],
            'manual fence from another account/repository')
    for tag, field in [('COMMIT','commit'),('RUN','run_id'),('ATTEMPT','run_attempt')]:
        require(fence.get(field) == env('RECONCILE_PRIOR_'+tag), 'prior release identity not approved')
    require(type(fence.get('plan_sha256')) is str, 'original approved Plan SHA unavailable')
    require(exit_code == 0, 'Terraform detailed exit code not zero')
    zero_drift(plan)
    require(DIGEST.fullmatch(digest) is not None, 'invalid restored digest')
    require(live.get('decision') == 'ECS_TASK_DIGEST_HEALTH_VERIFIED' and
            live.get('registry_digest') == digest and live.get('desired_count') == 2 and
            live.get('running_count') == 2 and len(live.get('tasks', [])) == 2,
            'actual ECS tasks not confirmed healthy at restored digest')
    require(live.get('aws_account_id') == current['aws_account_id'], 'restored AWS identity wrong')
    for k in ('commit','run_id','run_attempt'):
        require(str(live.get(k)) == current[k], 'restored task proof from foreign reconciliation run')
    require(live.get('production_authorized') is False and live.get('release_authorized') is False,
            'restored proof must be staging only')
    return {'decision': 'MANUAL_AWS_AND_TERRAFORM_RECONCILED',
            'prior_commit': fence['commit'], 'prior_run_id': fence['run_id'],
            'prior_run_attempt': fence['run_attempt'], 'prior_plan_sha256': fence['plan_sha256'],
            'reconciler_commit': current['commit'], 'reconciler_run_id': current['run_id'],
            'reconciler_run_attempt': current['run_attempt'], 'repository': current['repository'],
            'aws_account_id': current['aws_account_id'], 'restored_registry_digest': digest,
            'terraform_exit_code': 0, 'live_aws_verified': True,
            'production_authorized': False, 'release_authorized': False}


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--fence',required=True)
    p.add_argument('--terraform-json',required=True)
    p.add_argument('--live-tasks',required=True)
    p.add_argument('--terraform-exit-code',type=int,required=True)
    p.add_argument('--digest',required=True)
    p.add_argument('--output',required=True)
    a=p.parse_args()
    try:
        from scripts.day37_fence import s3
        record=load(a.fence)
        real,_=s3().read()
        require(real == record, 'manual fence differs from actual S3 state')
        from scripts.day37_aws import check_ecr, service_readback
        account = env('DAY37_ACCOUNT_ID')
        repo = env('DAY37_ECR_REPOSITORY')
        cluster = env('DAY37_CLUSTER')
        uri = f"{account}.dkr.ecr.ap-northeast-1.amazonaws.com/{repo}@{a.digest}"
        # Original manual workflow checks Cosign already; recheck it here so a
        # standalone proof call cannot bypass the release-signature requirement.
        subprocess.run(['cosign', 'verify',
                        '--certificate-identity',
                        f"https://github.com/{env('GITHUB_REPOSITORY')}/.github/workflows/day37-aws-staging.yml@refs/heads/main",
                        '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                        uri], check=True, capture_output=True, timeout=120)
        check_ecr(repo,account)
        fresh = service_readback(account,cluster,env('DAY37_SERVICE'),
                                 env('DAY37_ALB_TARGET_GROUP_ARN'),uri,2)
        prior = load(a.live_tasks)
        require(fresh.get('task_definition') == prior.get('task_definition') and
                fresh.get('tasks') == prior.get('tasks') and
                fresh.get('registry_digest') == prior.get('registry_digest'),
                'ECS task set drifted since independent verification')
        result=build(record,load(a.terraform_json),fresh,a.terraform_exit_code,a.digest)
        write(a.output,result)
        return 0
    except (Blocked,TypeError,ValueError,KeyError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        print('BLOCKED: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
