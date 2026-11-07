"""Proof that an ECS rollback target is *this* failed release, not a later one.

Strict comparison with the durable failed-plan image digest and original healthy
Task Definition. Does not modify ECS; update-service remains delegated to the
existing day37_aws.recover after this guard returns restore_required=true.
"""
from __future__ import annotations
import argparse
import re
import sys
from scripts.day37_fence import Blocked, DIGEST, current_identity, env, load, require, write


def examine(fence: dict, checkpoint: dict, ecs_service: dict, task_definition: dict | None) -> dict:
    current=current_identity()
    require(fence.get('state')=='ACTIVE' and fence.get('phase')=='deploy',
            'no ACTIVE deployment fence')
    for key in ('commit','run_id','run_attempt','aws_account_id'):
        require(str(fence.get(key))==current[key] and str(checkpoint.get(key))==current[key],
                'foreign failed-release/checkpoint identity')
    require(checkpoint.get('cluster')==env('DAY37_CLUSTER') and
            checkpoint.get('service')==env('DAY37_SERVICE'), 'wrong ECS service')
    require(checkpoint.get('exists') is True,'no previous healthy Task Definition')
    expected_digest=fence.get('image_digest')
    require(type(expected_digest) is str and DIGEST.fullmatch(expected_digest) is not None,
            'failed release digest missing')
    require(ecs_service.get('status')=='ACTIVE' and
            ecs_service.get('serviceName')==env('DAY37_SERVICE'),
            'foreign/inactive ECS service')
    old=checkpoint.get('previous_task_definition')
    family=f'arn:aws:ecs:ap-northeast-1:{current["aws_account_id"]}:task-definition/cv-ota-staging'
    require(type(old) is str and old.startswith(family), 'unsafe old ECS task family')
    task=ecs_service.get('taskDefinition')
    require(type(task) is str and task.startswith(family), 'unsafe current ECS task family')
    old_count=checkpoint.get('previous_desired_count')
    require(type(old_count) is int and old_count>=1, 'invalid previous service count')
    if task==old:
        require(ecs_service.get('desiredCount')==old_count,
                'old ECS service desired count changed; manual reconciliation required')
        return {'decision':'BLOCKED_ALREADY_PREVIOUS_TASK','restore_required':False,
                'production_authorized':False,'release_authorized':False}
    require(type(task_definition) is dict,'current ECS Task Definition is not independently verified')
    require(task_definition.get('taskDefinitionArn')==task,'Task Definition readback differs')
    containers=task_definition.get('containerDefinitions')
    require(type(containers) is list and len(containers)==1 and
            containers[0].get('name')=='vehicle-api', 'unexpected ECS container layout')
    image=containers[0].get('image','')
    expected_uri=(f'{current["aws_account_id"]}.dkr.ecr.ap-northeast-1.amazonaws.com/'
                  f'{env("DAY37_ECR_REPOSITORY")}@{expected_digest}')
    require(image==expected_uri,
            'ECS currently points to a foreign/later/different image; no rollback')
    return {'decision':'EXACT_FAILED_RELEASE_RESTORE_ALLOWED','restore_required':True,
            'target_task_definition':old,'current_task_definition':task,
            'image_digest':expected_digest, 'production_authorized':False,'release_authorized':False}


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--checkpoint',required=True)
    p.add_argument('--fence',required=True)
    p.add_argument('--output',required=True)
    a=p.parse_args()
    try:
        fence=load(a.fence);checkpoint=load(a.checkpoint)
        from scripts.day37_aws import aws
        response=aws('ecs','describe-services','--cluster',env('DAY37_CLUSTER'),
                     '--services',env('DAY37_SERVICE'))
        rows=response.get('services',[])
        require(not response.get('failures') and len(rows)==1,'ambiguous/missing ECS service')
        task=rows[0].get('taskDefinition','')
        old=checkpoint.get('previous_task_definition')
        definition=None
        if task!=old:
            response=aws('ecs','describe-task-definition','--task-definition',task)
            definition=response.get('taskDefinition')
        decision=examine(fence,checkpoint,rows[0],definition)
        write(a.output,decision)
        return 0
    except (Blocked,KeyError,TypeError,ValueError,OSError) as error:
        print('BLOCKED: ECS restore admission: '+str(error),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
