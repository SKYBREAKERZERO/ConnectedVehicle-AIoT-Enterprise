from __future__ import annotations

import hashlib
import json
import threading
from io import BytesIO

import pytest

from scripts.day37_fence import (Blocked, S3Fence, current_identity, identity_from_receipt,
                                 load, same)


class FakeError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class MemoryS3:
    def __init__(self):
        self.lock = threading.Lock()
        self.value = None
        self.version = 0

    def get_object(self, **kw):
        with self.lock:
            if self.value is None:
                raise FakeError("NoSuchKey")
            b = self.value
            return {"Body": BytesIO(b), "ETag": '"' + hashlib.sha256(b).hexdigest() + '"',
                    "VersionId": f"v{self.version}"}

    def put_object(self, **kw):
        with self.lock:
            old = self.value
            if ("IfNoneMatch" in kw and old is not None) or (
                "IfMatch" in kw and (old is None or kw["IfMatch"] != '"'+hashlib.sha256(old).hexdigest()+'"')):
                raise FakeError("PreconditionFailed")
            assert kw["ServerSideEncryption"] == "aws:kms"
            assert kw["ExpectedBucketOwner"] == "123456789012"
            self.version += 1
            self.value = kw["Body"]
            return {"VersionId": f"v{self.version}"}


@pytest.fixture
def envsetup(monkeypatch):
    for k,v in {
        "GITHUB_SHA": "a"*40, "GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise",
        "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "DAY37_ACCOUNT_ID": "123456789012", "DAY37_APPROVED_PLAN_SHA": "b"*64,
        "DAY37_CLUSTER": "stagingcluster", "DAY37_SERVICE": "stagingservice"
    }.items(): monkeypatch.setenv(k,v)
    return current_identity()


@pytest.fixture
def receipt_data(envsetup, tmp_path):
    summary = tmp_path / 'summary.json'
    summary.write_text(json.dumps({'phase':'deploy','decision':'NON_DESTRUCTIVE_TERRAFORM_PLAN',
                                   'image_digest':'sha256:'+'d'*64}))
    checkpoint = tmp_path / 'checkpoint.json'
    checkpoint.write_text(json.dumps({**{k:envsetup[k] for k in ('commit','run_id','run_attempt','aws_account_id')},
                           'cluster':'stagingcluster','service':'stagingservice','exists':True,
                           'previous_task_definition':'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/cv-ota-staging:1',
                           'previous_desired_count':2}))
    release={'commit':'a'*40,'registry_digest':'sha256:'+'d'*64,
             'image_uri':'123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/cv-staging@sha256:'+'d'*64,
             'signature_verified':True}
    rcpt={'decision':'PRIVATE_VERSIONED_PLAN_STORED','phase':'deploy','commit':'a'*40,
          'run_id':'77','run_attempt':'1','aws_account_id':'123456789012',
          'plan_sha256':'b'*64,'policy_sha256':hashlib.sha256(summary.read_bytes()).hexdigest(),
          'image_digest':'sha256:'+'d'*64}
    return rcpt, str(summary), release, str(checkpoint)


def test_real_transport_receipt_schema(envsetup,receipt_data):
    r,s,rel,cp=receipt_data
    got=identity_from_receipt(r,'deploy',s,rel,cp)
    assert got['policy_sha256']==r['policy_sha256']
    assert got['checkpoint_sha256']==hashlib.sha256(open(cp,'rb').read()).hexdigest()


@pytest.mark.parametrize('mutator',[
    lambda r,rel: r.update(plan_sha256='e'*64),
    lambda r,rel: r.update(policy_sha256='0'*64),
    lambda r,rel: r.update(image_digest='sha256:'+'f'*64),
    lambda r,rel: rel.update(signature_verified=False),
    lambda r,rel: r.update(run_attempt='2'),
])
def test_bad_receipt_refused(envsetup,receipt_data,mutator):
    r,s,rel,cp=receipt_data
    mutator(r,rel)
    with pytest.raises(Blocked): identity_from_receipt(r,'deploy',s,rel,cp)


def test_checkpoint_necessary(envsetup,receipt_data):
    r,s,rel,cp=receipt_data
    with pytest.raises(Blocked): identity_from_receipt(r,'deploy',s,rel)


@pytest.fixture
def fence():
    return S3Fence(MemoryS3(),'staging-bucket','my/key','arn:kms','123456789012')


def identity(envsetup,receipt_data):
    r,s,rel,cp=receipt_data
    return identity_from_receipt(r,'deploy',s,rel,cp)


def proof(ident):
    return {**ident,'decision':'AWS_AND_TERRAFORM_RECONCILED','terraform_exit_code':0,
            'live_aws_verified':True,'production_authorized':False,'release_authorized':False}


def test_s3_versioned_cas_active_and_restart(envsetup,receipt_data,fence):
    i=identity(envsetup,receipt_data)
    fence.mark(i)
    with pytest.raises(Blocked): fence.clear_check()
    another=S3Fence(fence.client,fence.bucket,fence.key,fence.kms,fence.account)
    with pytest.raises(Blocked): another.mark({**i,'run_id':'88'})


def test_s3_concurrent_writers_only_one(envsetup,receipt_data,fence):
    i=identity(envsetup,receipt_data)
    outcomes=[]
    def worker(n):
        try:
            fence.mark({**i,'run_id':str(200+n)})
            outcomes.append(True)
        except Blocked:
            outcomes.append(False)
    threads=[threading.Thread(target=worker,args=(n,)) for n in range(15)]
    for t in threads:t.start()
    for t in threads:t.join()
    assert outcomes.count(True)==1


def test_s3_proof_mismatch_leaves_active(envsetup,receipt_data,fence):
    i=identity(envsetup,receipt_data)
    fence.mark(i)
    for update in ({'terraform_exit_code':2},{'live_aws_verified':False},
                   {'plan_sha256':'e'*64},{'production_authorized':True}):
        with pytest.raises(Blocked): fence.close(i,{**proof(i),**update})
    assert fence.read()[0]['state']=='ACTIVE'


def test_s3_valid_close_prevents_replay(envsetup,receipt_data,fence):
    i=identity(envsetup,receipt_data)
    fence.mark(i)
    fence.close(i,proof(i))
    fence.clear_check()
    with pytest.raises(Blocked): fence.mark(i)
    fence.mark({**i,'run_id':'100'})


def test_pre_apply_checkpoint_hash_bound_to_recovery(envsetup,receipt_data,fence,tmp_path):
    i=identity(envsetup,receipt_data)
    r,s,rel,cp=receipt_data
    stored=fence.mark(i)
    assert fence.recovery_check(cp,stored)['state']=='ACTIVE'
    with pytest.raises(Blocked): fence.recovery_check(cp,{**stored,'plan_sha256':'e'*64})
    cp_file=tmp_path/'changed.json'
    original=json.loads(open(cp).read());original['previous_desired_count']=1
    cp_file.write_text(json.dumps(original))
    with pytest.raises(Blocked): fence.recovery_check(str(cp_file),stored)


def test_recovery_without_preexisting_service_blocked(envsetup,receipt_data,fence,tmp_path):
    i=identity(envsetup,receipt_data)
    r,s,rel,cp=receipt_data
    obj=json.loads(open(cp).read());obj['exists']=False
    p=tmp_path/'absent.json';p.write_text(json.dumps(obj))
    from scripts.day37_fence import digest_file
    absent_ident={**i,'checkpoint_sha256':digest_file(p)}
    stored=fence.mark(absent_ident)
    with pytest.raises(Blocked,match='manual reconciliation'): fence.recovery_check(str(p),stored)
