from pathlib import Path
root=Path(__file__).resolve().parents[1]
def replace_once(path,old,new,tag):
 s=path.read_text()
 if s.count(old)!=1: raise RuntimeError(f'{tag}: expected exactly one anchor, got {s.count(old)}')
 path.write_text(s.replace(old,new,1))
f=root/'scripts/day37_fence.py'
replace_once(f, '''    role = "bootstrap" if phase == "bootstrap" else "recovery"
    require(arn.startswith(f"arn:aws:sts::{account}:assumed-role/cv-ota-staging-{role}/"),
            "only reviewed phase-specific Role may close a fence")''', '''    require(phase in ("bootstrap", "deploy"), "invalid closure phase")
    # Apply principals MUST NOT be able to certify/close their own Fence.
    require(arn.startswith(f"arn:aws:sts::{account}:assumed-role/cv-ota-staging-recovery/"),
            "only independently approved Recovery Role may close a fence")''','independent closure')
replace_once(f, '''    manual = sub.add_parser("manual-close")
    manual.add_argument("--fence", required=True)''', '''    manual = sub.add_parser("manual-close")
    manual.add_argument("--phase", choices=("deploy", "bootstrap"), required=True)
    manual.add_argument("--fence", required=True)''','manual phase argument')
replace_once(f, '''        elif args.cmd == "manual-close":
            require_closure_role("deploy")
            record = load(args.fence)
            proof = load(args.proof)
            live, etag = fence.read()
            require(live == record and live.get("state") == "ACTIVE", "manual fence differs from S3")
            require(proof.get("decision") == "MANUAL_AWS_AND_TERRAFORM_RECONCILED" and
                    proof.get("terraform_exit_code") == 0 and proof.get("live_aws_verified") is True,
                    "manual proof not reconciled")''','''        elif args.cmd == "manual-close":
            require_closure_role(args.phase)
            record = load(args.fence)
            proof = load(args.proof)
            live, etag = fence.read()
            require(record.get("phase") == args.phase, "manual reconciliation phase mismatch")
            require(live == record and live.get("state") == "ACTIVE", "manual fence differs from S3")
            expected_decision = ("MANUAL_AWS_AND_TERRAFORM_RECONCILED" if args.phase == "deploy"
                                 else "MANUAL_BOOTSTRAP_AWS_AND_TERRAFORM_RECONCILED")
            require(proof.get("decision") == expected_decision and
                    proof.get("terraform_exit_code") == 0 and proof.get("live_aws_verified") is True,
                    "manual proof not reconciled")''','manual phase')
replace_once(f, '''            require(proof.get("restored_registry_digest") == env("RECONCILE_DIGEST") and
                    DIGEST.fullmatch(proof["restored_registry_digest"]) is not None,
                    "unapproved restored ECR digest")''','''            if args.phase == "deploy":
                require(proof.get("restored_registry_digest") == env("RECONCILE_DIGEST") and
                        DIGEST.fullmatch(proof["restored_registry_digest"]) is not None,
                        "unapproved restored ECR digest")
            else:
                require(proof.get("restored_registry_digest") is None and
                        record.get("image_digest") is None,
                        "bootstrap cannot assert a running image digest")''','phase digest')
# Add S3 account KMS confirmation beyond location config (bucket version already checked) in readback; existing protected key.
# Manual-deploy producer explicitly passes --phase.
manual=root/'scripts/day37_manual_proof.py'
replace_once(manual, '''    require(fence.get('schema') == 2 and fence.get('state') == 'ACTIVE', 'not an ACTIVE v2 fence')''', '''    require(fence.get('schema') == 2 and fence.get('state') == 'ACTIVE' and
            fence.get('phase') == 'deploy', 'manual ECS rollback may only close deploy fence')''','manual proof deploy phase')
# Gate must include new independent job. Old day37_gate.final remains unmodified and receives its 10 expected keys via adapter.
g=root/'scripts/day37_release_guard.py'
replace_once(g, '''"bootstrap": {"source", "admission", "plan", "bootstrap"},''', '''"bootstrap": {"source", "admission", "plan", "bootstrap", "bootstrap_close"},''','final job status bootstrap')
replace_once(g, '''"deploy", "verify", "close", "recovery"}''','''"deploy", "verify", "close", "recovery", "bootstrap_close"}''','final job set')
# Keep the CLI final-check method; main workflow must call enterprise wrapper so 11 => 12 expected jobs.
print('HARDENED',f,manual,g)
