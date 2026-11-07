"""Offline, reviewable YAML source patch for the real Day37 feature branch.

Run from repo root: python tools/apply_p0_to_worktree.py --apply
No AWS calls and no Git commit/push. Refuses unknown source shapes.
"""
from __future__ import annotations

import argparse
from pathlib import Path

MAIN = Path('.github/workflows/day37-aws-staging.yml')
MANUAL = Path('.github/workflows/day37-reconcile.yml')


def insist(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError('BLOCKED: incompatible source: ' + message)


def repl(source: str, old: str, new: str, label: str, count: int = 1) -> str:
    matches = source.count(old)
    insist(matches == count, f'{label}: expected {count} match, found {matches}')
    return source.replace(old, new)


def patch_main(raw: str) -> str:
    insist('name: Day37 AWS Staging enterprise release' in raw, 'wrong main workflow')
    insist('day37_fence mark' not in raw, 'already patched: inspect diff before reapplying')
    text = raw.replace('python -m scripts.day37_plan_transport clear-check', 'python -m scripts.day37_fence clear-check')
    insist('python -m scripts.day37_plan_transport clear-check' not in text, 'old clear-check remains')

    for line in text.splitlines():
        if 'python -m compileall -q scripts/day37_gate.py ' in line:
            old=line
            break
    else:
        raise ValueError('BLOCKED: source compile step not found')
    extra=' scripts/day37_fence.py scripts/day37_release_guard.py scripts/day37_reconcile.py scripts/day37_manual_proof.py scripts/day37_plan_transport.py'
    text=repl(text,old,old+extra,'source compile')
    lines=text.splitlines()
    tests=[x for x in lines if 'python -m pytest tests/unit/test_day37_gate.py' in x]
    insist(len(tests)==1,'source test step')
    new_tests=' tests/unit/test_day37_fence.py tests/unit/test_day37_release_guard_p0.py tests/unit/test_day37_reconcile_p0.py tests/unit/test_day37_manual_proof.py tests/unit/test_day37_workflow_p0.py'
    text=repl(text,tests[0],tests[0].replace(' -q',new_tests+' -q'),'source P0 tests')

    # Always prove that real saved-plan receipt is bound to the exact approved
    # policy summary. Persist the S3 ACTIVE fence before bootstrap mutation.
    fetch_b='python -m scripts.day37_plan_transport fetch --phase bootstrap --receipt .day37/reviewed-plan/receipt.json --summary .day37/reviewed-plan/plan-summary.json --sha256 "$DAY37_APPROVED_PLAN_SHA" --output .day37/private/bootstrap.tfplan'
    before_b=("\n        python -m scripts.day37_release_guard binding --phase bootstrap --receipt .day37/reviewed-plan/receipt.json --summary .day37/reviewed-plan/plan-summary.json --sha256 \"$DAY37_APPROVED_PLAN_SHA\""
              "\n        python -m scripts.day37_fence mark --phase bootstrap --receipt .day37/reviewed-plan/receipt.json --summary .day37/reviewed-plan/plan-summary.json --output .day37/bootstrap/fence.json")
    text=repl(text,fetch_b,fetch_b+before_b,'bootstrap receipt before fence')
    bootstrap_verify='python -m scripts.day37_aws bootstrap-verify --output .day37/bootstrap/bootstrap.json'
    bootstrap_close='''
        # Terraform refresh and every managed dependency must be NO-OP; failures
        # leave S3 fence ACTIVE until independently reviewed reconciliation.
        export TF_VAR_enable_service=false TF_VAR_desired_count=0
        set +e
        terraform -chdir="${DAY37_TF_ROOT}" plan -detailed-exitcode -input=false -lock-timeout=30s -no-color -out="${PWD}/.day37/bootstrap/no-drift.tfplan" > .day37/bootstrap/terraform-private.log 2>&1
        RC=$?
        set -e
        [[ "$RC" -eq 0 ]] || { echo 'BLOCKED: bootstrap partially applied or Terraform drift' >&2; exit 1; }
        terraform -chdir="${DAY37_TF_ROOT}" show -json "${PWD}/.day37/bootstrap/no-drift.tfplan" > .day37/bootstrap/no-drift.json
        python -m scripts.day37_reconcile --phase bootstrap --fence .day37/bootstrap/fence.json --terraform-json .day37/bootstrap/no-drift.json --terraform-exit-code "$RC" --output .day37/bootstrap/proof.json
        python -m scripts.day37_fence close --receipt .day37/bootstrap/fence.json --proof .day37/bootstrap/proof.json --output .day37/bootstrap/closed-fence.json'''
    text=repl(text,bootstrap_verify,bootstrap_verify+bootstrap_close,'bootstrap proof')
    text=repl(text,'path: .day37/bootstrap/bootstrap.json',
              'path: |\n          .day37/bootstrap/bootstrap.json\n          .day37/bootstrap/closed-fence.json\n          .day37/bootstrap/proof.json',
              'bootstrap evidence artifacts')
    # New fence identity includes the pre-Apply checkpoint hash, real receipt
    # image_digest and immutable verified release digest.
    old_d='python -m scripts.day37_plan_transport mark-fence --phase deploy --receipt .day37/reviewed-plan/receipt.json --output .day37/deploy/fence.json'
    new_d='''python -m scripts.day37_release_guard binding --phase deploy --receipt .day37/reviewed-plan/receipt.json --summary .day37/reviewed-plan/plan-summary.json --sha256 "$DAY37_APPROVED_PLAN_SHA" --release .day37/publish/release.json --checkpoint .day37/deploy/checkpoint.json
        python -m scripts.day37_fence mark --phase deploy --receipt .day37/reviewed-plan/receipt.json --summary .day37/reviewed-plan/plan-summary.json --release .day37/publish/release.json --checkpoint .day37/deploy/checkpoint.json --output .day37/deploy/fence.json'''
    text=repl(text,old_d,new_d,'deployment mark fence')
    # Independently run the existing AWS verifier AGAIN at close time and
    # compare the saved binary plan against refreshed Terraform State.
    close_old='python -m scripts.day37_plan_transport close-fence --receipt .day37/fence/fence.json --verified'
    close_new='''terraform -chdir="${DAY37_TF_ROOT}" show -json "${PWD}/.day37/closure/zero-drift.tfplan" > .day37/closure/zero-drift.json
        python -m scripts.day37_reconcile --phase deploy --fence .day37/fence/fence.json --terraform-json .day37/closure/zero-drift.json --terraform-exit-code "$CODE" --release .day37/publish/release.json --output .day37/closure/proof.json
        python -m scripts.day37_release_guard closure --receipt .day37/fence/fence.json --proof .day37/closure/proof.json --sha256 "$DAY37_APPROVED_PLAN_SHA" --release .day37/publish/release.json
        python -m scripts.day37_fence close --receipt .day37/fence/fence.json --proof .day37/closure/proof.json --output .day37/closure/fence-closed.json'''
    text=repl(text,close_old,close_new,'deploy closed fence')

    text=repl(text, 'path: .day37/closure/closed.json',
              'path: |\n          .day37/closure/closed.json\n          .day37/closure/fence-closed.json\n          .day37/closure/proof.json',
              'deploy closure evidence artifacts')
    # Recovery should not infer that a checkpoint exists merely because deploy
    # failed. Read Artifact metadata, then compare its bytes with live S3 fence.
    beginning=text.index('\n  recovery:')
    ending=text.index('\n  gate:',beginning)
    recovery=text[beginning:ending]
    recovery=recovery.replace('      id-token: write', '      actions: read\n      id-token: write', 1)
    old='''    - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
      with:
        name: day37-checkpoint-${{ github.run_id }}-${{ github.run_attempt }}
        path: .day37/recovery
    - name: Revert only ECS service to previous already-healthy Task Definition
      run: python -m scripts.day37_aws recover --checkpoint .day37/recovery/checkpoint.json --output .day37/recovery/recovery.json'''
    new='''    - name: Enumerate exact same-run checkpoint Artifact (missing != healthy)
      id: checkpoint
      env:
        GH_TOKEN: ${{ github.token }}
      run: |
        set -euo pipefail
        mkdir -p .day37/recovery
        python -m scripts.day37_release_guard checkpoint --repo "$GITHUB_REPOSITORY" --run-id "$GITHUB_RUN_ID" --attempt "$GITHUB_RUN_ATTEMPT" --output .day37/recovery/checkpoint-status.json
        echo "exists=$(python -c 'import json;print(json.load(open(".day37/recovery/checkpoint-status.json"))["checkpoint_exists"])')" >> "$GITHUB_OUTPUT"
    - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
      if: ${{ steps.checkpoint.outputs.exists == 'true' }}
      with:
        name: day37-checkpoint-${{ github.run_id }}-${{ github.run_attempt }}
        path: .day37/recovery
    - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
      if: ${{ steps.checkpoint.outputs.exists == 'true' }}
      with:
        name: day37-fence-${{ github.run_id }}-${{ github.run_attempt }}
        path: .day37/recovery/fence
    - name: 'No checkpoint - block and require manual inspection (no rollback)'
      if: ${{ steps.checkpoint.outputs.exists == 'false' }}
      run: python -m scripts.day37_release_guard skipped-recovery --output .day37/recovery/recovery.json
    - name: Revert only with exact original Task Definition and live ACTIVE S3 fence
      if: ${{ steps.checkpoint.outputs.exists == 'true' }}
      run: |
        set -euo pipefail
        python -m scripts.day37_fence recovery-check --checkpoint .day37/recovery/checkpoint.json --fence .day37/recovery/fence/fence.json
        python -m scripts.day37_aws recover --checkpoint .day37/recovery/checkpoint.json --output .day37/recovery/recovery.json'''
    recovery=repl(recovery,old,new,'recovery checkpoint and fence')
    text=text[:beginning]+recovery+text[ending:]
    # P0 helpers import boto3. `setup-python` alone does NOT install boto3;
    # use the repository's pinned, hash-locked CI runtime in every AWS job
    # executing the new code. Publish/source already use it.
    for job_name in ("plan", "bootstrap", "deploy_plan", "deploy", "close", "recovery"):
        heading = "\n  " + job_name + ":"
        start = text.index(heading)
        import re
        next_job = re.search(r"\n  [a-z_]+:", text[start + len(heading):])
        end = start + len(heading) + next_job.start() if next_job else len(text)
        section = text[start:end]
        python_setup = "        python-version: '3.12'"
        insist(section.count(python_setup) == 1, job_name + " setup-python stanza")
        section = section.replace(python_setup, python_setup +
                                  "\n    - uses: ./.github/actions/setup-ci-runtime", 1)
        text = text[:start] + section + text[end:]
    # Standalone guard cannot authorize production; existing gate still owns
    # cryptographic evidence and correct Day37 mode-specific decisions.
    final='python -m scripts.day37_gate final --mode "${DAY37_MODE}" --output .day37/final.json --folder .day37/check'
    text=repl(text,final,final+'\n        python -m scripts.day37_release_guard final-check --mode "${DAY37_MODE}" --folder .day37/check --final .day37/final.json','final result binding')
    return text


def patch_manual(raw: str) -> str:
    insist('Day37 manual AWS Staging Terraform recovery reconciliation' in raw,'wrong manual workflow')
    insist('day37_fence manual-close' not in raw,'manual workflow already patched')
    # Manual recovery also imports boto3; install only from pinned ci.lock.
    manual_setup = "          python-version: '3.12'"
    insist(raw.count(manual_setup) == 1, 'manual setup-python stanza')
    raw = raw.replace(manual_setup, manual_setup +
                      "\n      - uses: ./.github/actions/setup-ci-runtime", 1)
    text=repl(raw,'python -m scripts.day37_plan_transport read-fence --output .day37/manual/fence.json',
              'python -m scripts.day37_fence read-fence --output .day37/manual/fence.json','manual read S3 fence')
    before='''          python -m scripts.day37_plan_transport close-fence --verified --manual \\
            --prior-commit "$RECONCILE_PRIOR_COMMIT" --prior-run-id "$RECONCILE_PRIOR_RUN" --prior-attempt "$RECONCILE_PRIOR_ATTEMPT" \\
            --receipt .day37/manual/fence.json'''
    after='''          terraform -chdir="${DAY37_TF_ROOT}" show -json "${PWD}/.day37/manual/zero-drift.tfplan" > .day37/manual/zero-drift.json
          python -m scripts.day37_manual_proof --fence .day37/manual/fence.json --terraform-json .day37/manual/zero-drift.json --terraform-exit-code "$RESULT" --live-tasks .day37/manual/verified.json --digest "$RECONCILE_DIGEST" --output .day37/manual/manual-proof.json
          python -m scripts.day37_fence manual-close --phase deploy --fence .day37/manual/fence.json --proof .day37/manual/manual-proof.json --output .day37/manual/fence-closed.json'''
    return repl(text,before,after,'manual CAS closure')


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo',type=Path,default=Path('.'))
    ap.add_argument('--apply',action='store_true',help='Write files into local repo; default is parse/check only')
    ap.add_argument('--output-dir',type=Path,default=Path('/mnt/data/day37_p0_preview'))
    args=ap.parse_args()
    updated=[]
    for name,func in ((MANUAL,patch_manual),):
        src=args.repo/name
        insist(src.is_file(),str(name)+' not found')
        data=func(src.read_text(encoding='utf-8'))
        # Both modified YML files parse, before any file is written.
        import yaml
        doc=yaml.safe_load(data)
        insist(type(doc) is dict and 'jobs' in doc, 'invalid YAML '+str(name))
        updated.append((name,data))
    for name,data in updated:
        dest=(args.repo if args.apply else args.output_dir)/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(data,encoding='utf-8')
        print(('UPDATED' if args.apply else 'PREVIEW'),dest)
    print('DONE: AWS/Apply not invoked. Review diff; run tests before Git commit.')

if __name__=='__main__':
    main()
