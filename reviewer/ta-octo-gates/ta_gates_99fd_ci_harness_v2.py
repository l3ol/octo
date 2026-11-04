#!/usr/bin/env python3
"""Founder-appointed TA chat GATES G4 independent evidence harness.

V2: derived ephemeral CI pin + original Ops SHA reference, never Ops private paths.
This file belongs ONLY on reviewer/ta-octo-gates-20261101. It does not modify
the PR12 candidate. A passed Builder test replay is labeled corroboration,
not an independent verdict. No production Path B, production merges or keys.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

TIP = "99fd6a48eca58b88b6730d88875672fb72da9bac"
TREE = "2ba7c96c9c908aedec7f475915f2addb7b70ccf4"
BASE = "5443c9b4dde7fc208a0a72457c87904650829f77"
CONTRACT = "c1e357b40dba46e2b9ce825cd428c877ba20f4ecf7de2044e0abea28847ace8d"
OPS_ORIGINAL_MANIFEST_SHA = "6250b8d339dc5278c4aaf2a00577144ff5ce11c9500d7b5f0b3e185984a29763"
GATES_TREE = "3e8cc2c58e83e78e91caa9d6370cb9611178d20d"
ARTIFACT_SHA = "42368539d65f50337ea1fbe92e4cf41fba086869aafdb00595fcf0fbb51ed0a8"
CONFIG_SHA = "2feb73d01b2a717b0219253967770ad2da094dd137b918c4a3a35e1dd27ff59a"
ACCEPT_IDS = (
 "R-1 R-2 R-3 R-4 R-5 V-1 V-2 V-3 V-4 V-5 V-6 V-7 V-8 V-9 V-10 "
 "P-1 P-2 P-3 P-4 P-5 P-6 J-1 J-2 A-1 A-2 A-3 A-4 A-5 A-6 A-7 A-8 A-9 A-10 "
 "G-1 G-2 G-3 M-1 M-2 I-1 I-2 L-1 L-2"
).split()
CASE_MAP = {
 **{n: f"test_scene_{n:02d}_" for n in range(1, 30)},
 23: "test_scene_23_30_31_32_isomorphism",
 34: "test_scene_34_and_35_recovery_verification",
 35: "test_scene_34_and_35_recovery_verification",
 **{n: "test_scene_23_30_31_32_isomorphism" for n in (30,31,32)},
 33: "test_scene_33_reopen_when_four_conditions_hold",
 **{n: "test_scenes_36_to_39_kill_lines" for n in (36,37,38,39)},
 **{n: "test_scenes_40_to_43_initial_activation" for n in (40,41,42,43)}
}
for n in (6,): CASE_MAP[n] = "test_scene_06_positive_and_reverse_without_pass"
CASE_MAP[9] = "test_scene_09_unknown_or_closed_task"
CASE_MAP[11] = "test_scene_11_brain_or_backup_content"
CASE_MAP[13] = "test_scene_13_forbidden_paths_and_manifest_exception"
CASE_MAP[15] = "test_scene_15_untrusted_issuer_and_tampered_receipt"
CASE_MAP[23] = CASE_MAP[30]
CASE_MAP[25] = "test_scene_25_builder_acceptance_separation"
CASE_MAP[26] = "test_scene_26_pin_fail_closed_and_path_filter"
CASE_MAP[27] = "test_scene_27_compare_and_merge_bypass_rejected"
CASE_MAP[28] = "test_scene_28_recovery_missing"
CASE_MAP[29] = "test_scene_29_board_invisible"
CASE_MAP[24] = "test_scene_24_path_b_disabled_by_default_and_on_production"
CASE_MAP[18] = "test_scene_18_head_moved_before_merge"
CASE_MAP[19] = "test_scene_19_already_consumed_is_the_only_failure"
CASE_MAP[20] = "test_scene_20_concurrent_receipt_one_winner"
CASE_MAP[21] = "test_scene_21_sha_mismatch_substitution"
CASE_MAP[22] = "test_scene_22_binding_inconsistent"

def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(65536), b""): h.update(b)
    return h.hexdigest()

def cmd(argv: list[str], *, cwd: Path | None = None, seconds: int = 80) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, capture_output=True, timeout=seconds, check=False)

def git(repo: Path, *args: str) -> str:
    r = cmd(["git", "-C", str(repo), *args], seconds=22)
    if r.returncode:
        raise RuntimeError(f"git {args[0]} rc={r.returncode}: {r.stderr.decode(errors='replace')[:300]}")
    return r.stdout.decode().strip()

def check(name: str, cond: bool, details: dict | None = None) -> None:
    assertions.append({"name": name, "pass": bool(cond), "details": details or {}})

p = argparse.ArgumentParser()
p.add_argument("--candidate", required=True)
p.add_argument("--pin-loadpath", required=True)
p.add_argument("--output", required=True)
p.add_argument("--reviewer-script-sha", required=True)
p.add_argument("--workflow-sha", required=True)
p.add_argument("--lineage-receipt", required=True)
p.add_argument("--materializer-sha", required=True)
args = p.parse_args()
candidate, pinpath, out = (Path(v).resolve() for v in (args.candidate, args.pin_loadpath, args.output))
pinroot = pinpath/"pins"/TIP
ci_manifest_path = pinpath/"manifests"/"pin99fd-ci.json"
lineage_path = Path(args.lineage_receipt).resolve()
out.mkdir(parents=True, exist_ok=True)
case_dir = out/"scenes"
case_dir.mkdir(parents=True, exist_ok=True)
assertions, scene_rows, independent = [], [], []
started=utc()
facts={"reviewer":"TA-CHAT-REVIEWER-OCTO-20261101-01","tip":TIP,"tree":TREE,"base":BASE,
       "frozen_v6_sha256":CONTRACT,"reviewer_script_sha256":args.reviewer_script_sha,
       "workflow_sha256":args.workflow_sha,"started_at":started,
       "ci_actor":os.environ.get("GITHUB_ACTOR","NOT_EXPOSED"),
       "ci_triggering_actor":os.environ.get("GITHUB_TRIGGERING_ACTOR","NOT_EXPOSED"),
       "github_run_id":os.environ.get("GITHUB_RUN_ID"),
       "github_run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT"),
       "github_sha_reviewer_branch":os.environ.get("GITHUB_SHA"),
       "github_ref_reviewer_branch":os.environ.get("GITHUB_REF"),
       "euid":os.geteuid(),"egid":os.getegid(),"groups":os.getgroups(),
       "mount_ns":os.readlink("/proc/self/ns/mnt"),
       "net_ns":os.readlink("/proc/self/ns/net"),
       "host_mount_ns":os.environ.get("GATES_HOST_MNT_NS"),
       "host_net_ns":os.environ.get("TA_HOST_NET_NS"),
       "harness_env":os.environ.get("GATES_RDONLY_NS"),
       "gate_dispatch":os.environ.get("GATES_ENTER_VIA"),
       "pin_readonly":bool(os.statvfs(pinpath).f_flag & os.ST_RDONLY),
       "candidate_readonly":bool(os.statvfs(candidate).f_flag & os.ST_RDONLY)}
status_caps=Path("/proc/self/status").read_text()
facts["effective_caps"]=next((l.split(":",1)[1].strip() for l in status_caps.splitlines() if l.startswith("CapEff:")),"UNKNOWN")
facts["uid_map"]=Path("/proc/self/uid_map").read_text().strip()
check("exact_commit",git(candidate,"rev-parse","HEAD")==TIP)
check("exact_tree",git(candidate,"rev-parse","HEAD^{tree}")==TREE)
check("exact_base",git(candidate,"cat-file","-t",BASE)=="commit" and
      cmd(["git","-C",str(candidate),"merge-base","--is-ancestor",BASE,TIP]).returncode==0)
check("candidate_no_modifications",git(candidate,"status","--porcelain=v1","--untracked-files=all")=="")
check("candidate_kernel_readonly",facts["candidate_readonly"])
check("pin_kernel_readonly",facts["pin_readonly"])
check("separate_mount_namespace",facts["host_mount_ns"] not in (None,facts["mount_ns"]))
check("separate_network_namespace",facts["host_net_ns"] not in (None,facts["net_ns"]))
check("official_entry",facts["harness_env"]=="1" and facts["gate_dispatch"] in ("twin","ops-enter"))
# CI manifest is regenerated under runner scratch. It is NOT the historical Ops file.
# Require a new manifest digest, bind it to separate byte-hashed lineage evidence,
# and exercise the actual fixed-tip pin loader with protected-module provenance.
derived_sha=sha_file(ci_manifest_path)
lineage=json.loads(lineage_path.read_bytes())
pin=json.loads(ci_manifest_path.read_bytes())
facts["ci_runtime_manifest_sha256"]=derived_sha
facts["ci_lineage_receipt_sha256"]=sha_file(lineage_path)
facts["ops_source_manifest_sha256_reference_only"]=OPS_ORIGINAL_MANIFEST_SHA
facts["materializer_script_sha256"]=args.materializer_sha
check("ci_derived_manifest_is_new",derived_sha!=OPS_ORIGINAL_MANIFEST_SHA)
check("ci_manifest_lineage",lineage.get("kind")=="TA_CI_99FD_DERIVED_PIN_LINEAGE_V1"
      and lineage.get("candidate_commit")==TIP and lineage.get("candidate_tree")==TREE
      and lineage.get("base_commit")==BASE
      and lineage.get("ci_runtime_manifest_sha256")==derived_sha
      and lineage.get("ops_original_manifest_sha256_reference_only")==OPS_ORIGINAL_MANIFEST_SHA
      and lineage.get("ops_original_manifest_bytes_imported") is False
      and lineage.get("ops_private_host_paths_imported") is False)
check("ci_manifest_expected_gate_digests",pin.get("artifact_digest")==ARTIFACT_SHA
      and pin.get("config_digest")==CONFIG_SHA
      and pin.get("gate_tree_sha")==GATES_TREE
      and pin.get("git_repo")==str(candidate) and pin.get("extract_root")==str(pinroot))
check("pin_manifest_binds_tip",pin.get("gates_pin_sha")==TIP and pin.get("pin_tree_sha")==TREE
      and pin.get("source_commit")==TIP)
check("pin_actual_tree",sha_file(pinroot/"gates"/"rules.py")==
      sha_file(candidate/"gates"/"rules.py"))
check("pin_tree_git_object",git(candidate,"rev-parse",f"{TIP}:gates") == pin.get("gate_tree_sha"))
try:
    from gates.tamper.loader import load_pin
    loaded=load_pin(external_manifest=pin,pin_loadpath=pinroot,
                    manifest_path=ci_manifest_path,
                    candidate_worktree=candidate,git_repo=candidate,
                    candidate_sha=TIP,base_sha=BASE,task_id="TA-GATES-REVIEW-99FD")
    details=getattr(loaded.result,"evidence",{}).get("details",{}) if loaded.result else {}
    check("G1_real_pin_loader",loaded.ok
          and loaded.runtime is not None
          and loaded.runtime.source=="pin_loadpath"
          and details.get("real_module_load") is True
          and details.get("candidate_code_used") is False,
          {"loaded_from":"CI_DERIVED_PIN_PATH","source":"REAL_ISOLATION_EVIDENCE",
           "ops_production_pin_proved":False})
except Exception as error:
    check("G1_real_pin_loader",False,{"exception":type(error).__name__})
check("acceptance_ids_exact",len(ACCEPT_IDS)==42 and len(set(ACCEPT_IDS))==42)
table=(candidate/"gates"/"acceptance_item_map.md").read_text()
observed=re.findall(r"(?m)^\|\s*([RVPAJGMIL]-\d+)\s*\|",table)
check("42_mapped_ids",sorted(observed)==sorted(ACCEPT_IDS),{"total":len(observed)})
check("43_scene_numbers",sorted(CASE_MAP)==list(range(1,44)))

# No network: netns has no external route. Verify without sending a packet.
r=cmd(["ip","route","show","default"],seconds=4)
check("no_network_default_route",r.returncode==0 and not r.stdout.strip(),
      {"rc":r.returncode,"route_sha256":sha_bytes(r.stdout)})
# Strong fail-closed gate: failures in mandatory containment stop before test replay.
critical={"exact_commit","exact_tree","exact_base","candidate_no_modifications",
          "candidate_kernel_readonly","pin_kernel_readonly","separate_mount_namespace",
          "separate_network_namespace","official_entry","ci_derived_manifest_is_new",
          "ci_manifest_lineage","ci_manifest_expected_gate_digests","G1_real_pin_loader",
          "pin_manifest_binds_tip","pin_tree_git_object","no_network_default_route"}
failed_critical=[v["name"] for v in assertions if v["name"] in critical and not v["pass"]]
if failed_critical:
    (out/"preflight.json").write_text(json.dumps({"facts":facts,"assertions":assertions,
        "failed_critical":failed_critical,"g4_pass":False},indent=2)+"\n")
    print("TA_REVIEWER_PREFLIGHT_BLOCKED "+",".join(failed_critical),flush=True)
    sys.exit(3)

# Independently authored targeted assertions (NOT Builder test results).
from gates.scope.decide import check_task_id_present,check_task_active,check_paths_in_range
from gates.verification.decide import check_candidate_binding,check_base_binding,check_trusted_issuer,check_unconsumed
from gates.policy.content import scan_secrets,scan_brain_or_backup,scan_kill_lines
from gates.policy.forbidden import evaluate_paths
from gates.integrity.board import Board,publish_board
from gates.integrity.recovery import verify_recovery
from gates.tamper.loader import load_pin
from gates.activation.state import ActivationState
from gates.activation.request import evaluate_for_landing,check_separation
from gates.rules import RULE_VERSION,RULE_DIGEST,CANONICAL_SHA256,CANONICAL_PATH
def probe(name: str, got, expected) -> None:
    independent.append({"name":name,"actual":got,"expected":expected,"pass":got==expected})
probe("canonical_policy",sha_file(CANONICAL_PATH),CANONICAL_SHA256)
probe("missing_task",check_task_id_present(None)["reason_code"],"SCOPE_MISSING_TASK_ID")
probe("closed_task",check_task_active("X",{"tasks":{"X":{"status":"closed"}}})[0]["reason_code"],"SCOPE_UNKNOWN_OR_CLOSED_TASK")
probe("out_of_scope",check_paths_in_range(["../../Brain"],["src/**"])["reason_code"],"SCOPE_OUT_OF_RANGE")
probe("wrong_candidate",check_candidate_binding({"candidate_sha":"f"*40},TIP,None)["reason_code"],"VERIFICATION_SHA_MISMATCH")
probe("wrong_base",check_base_binding({"base_sha":"f"*40},BASE)["reason_code"],"VERIFICATION_BASE_STALE")
probe("untrusted_issuer",check_trusted_issuer({"issuer":"untrusted"}, {})[0]["reason_code"],"VERIFICATION_UNTRUSTED_ISSUER")
class Taken:
    def is_consumed(self,rid): return True
probe("replay_consumed",check_unconsumed({"receipt_id":"used"},Taken())["reason_code"],
      "VERIFICATION_RECEIPT_ALREADY_CONSUMED")
# TEST_FIXTURE ONLY: deliberately synthetic AWS-shaped marker, never credential material.
probe("TEST_FIXTURE_synthetic_key",bool(scan_secrets("test",b"AKIA"+b"A"*16)),True)
probe("synthetic_brain",bool(scan_brain_or_backup("test",b"OCTO-BRAIN-RAW-v1")),True)
probe("forbidden_path",evaluate_paths(["../../escape"],[],RULE_DIGEST)["reason_code"],"POLICY_FORBIDDEN_PATH")
probe("funds_kill",bool(scan_kill_lines("x",b"stripe.PaymentIntent.create(amount=1)")),True)
ids={"candidate_sha":TIP,"base_sha":BASE,"task_id":"T-REVIEW","rule_version":RULE_VERSION,"rule_digest":RULE_DIGEST}
probe("production_path_b_blocked",evaluate_for_landing(
    ActivationState(environment="production"),irreversible=False,kill_category=None,**ids).reason_code,
    "ACTIVATION_PATH_B_DISABLED")
probe("default_path_b_false",ActivationState().path_b_enabled,False)
probe("absent_pin_rejects",load_pin(external_manifest={"gates_pin_sha":"UNSET_FAIL_CLOSED"},
    candidate_sha=TIP,base_sha=BASE).result.reason_code,"TAMPER_PIN_UNSET_OR_INVALID")
probe("missing_recovery_denied",verify_recovery(None,TIP,BASE,repo=str(candidate),board=Board(),
    rule_version=RULE_VERSION,task_id="T-REVIEW",rule_digest=RULE_DIGEST).reason_code,
    "INTEGRITY_RECOVERY_MISSING")
probe("board_invisible_denied",publish_board({},Board(visible=False),**ids).reason_code,
    "INTEGRITY_BOARD_INVISIBLE")
shared=ActivationState(builder_ids=frozenset({"builder"}),acceptance_ids=frozenset({"reviewer"}),
                       shared_write_principals=frozenset({"one_shared_writer"}))
probe("A2_shared_write_fixture_reject",check_separation(shared,**ids).decision,"REJECT")
overlap=ActivationState(builder_ids=frozenset({"same"}),acceptance_ids=frozenset({"same"}))
probe("A2_same_principal_fixture_reject",check_separation(overlap,**ids).decision,"REJECT")

# Real L1-35 on a completely disposable, NO-REMOTE Git replica, never main or Path B.
l1={"status":"NOT_RUN","reason":"not entered"}
try:
    from gates.integrity.drill import execute_recovery_drill
    root=out/"l1_disposable"
    root.mkdir()
    bare=root/"drill.git"
    cl=cmd(["git","clone","--quiet","--bare",str(candidate),str(bare)],seconds=30)
    if cl.returncode: raise RuntimeError("local_bare_clone_failed")
    git(bare,"remote","remove","origin")
    git(bare,"config","core.hooksPath","/dev/null")
    if git(bare,"remote")!="": raise RuntimeError("disposable_repo_has_remote")
    plan=execute_recovery_drill(bare,candidate_sha=TIP,base_sha=BASE,rollback_sha=BASE,
        evidence_dir=root/"evidence",board_dir=root/"board",
        receipt_id="TA-REVIEW-G4-L1-35")
    receipt=json.loads(Path(plan["drill_receipt_path"]).read_text())
    board_entry=json.loads(Path(plan["drill_board_path"]).read_text())
    board=Board()
    board.remember_drill(plan["drill_board_entry_id"],board_entry)
    verified=verify_recovery(plan,TIP,BASE,repo=str(bare),board=board,
        rule_version=RULE_VERSION,task_id="T-REVIEW",rule_digest=RULE_DIGEST)
    ok=(receipt["result"]=="PASS" and receipt["ref_before"]==BASE and
        receipt["ref_after"]==BASE and git(bare,"rev-parse","refs/drill/l1")==BASE and
        verified.decision=="PASS" and git(bare,"remote")=="")
    l1={"status":"PASS" if ok else "FAIL","verification_decision":verified.decision,
        "receipt_sha256":sha_file(Path(plan["drill_receipt_path"])),
        "board_sha256":sha_file(Path(plan["drill_board_path"])),
        "candidate_sha":TIP,"base_sha":BASE,"rollback_sha":BASE,
        "disposable_repo_no_remote":True,"path_b":False,"real_product_merge":False}
except Exception as exc:
    l1={"status":"FAIL","reason":type(exc).__name__+":"+str(exc)[:180]}
# Per-scene subprocess test replay. Each machine row binds a specific scene number.
# IMPORTANT: the execution uses candidate-authored pytest assertions, so "corroborated"
# is NOT equal to "independently authored acceptance PASS" for that scene.
case_src=(candidate/"tests/gates/test_scenes.py").read_text()
functions=re.findall(r"(?m)^def (test_(?:scene|scenes)_[a-zA-Z_0-9]+)\(",case_src)
for num in range(1,44):
    prefix=CASE_MAP[num]
    matched=[f for f in functions if f.startswith(prefix)]
    name=f"scene_{num:02d}"
    record={"scene":num,"source_case":prefix,"kind":"BUILDER_CASE_REPLAY_NOT_INDEPENDENT_ACCEPTANCE",
            "started_at":utc(),"status":"NOT_RUN"}
    if len(matched)!=1:
        record["status"]="BLOCKED"
        record["reason"]="case_not_unique:"+repr(matched)
    else:
        full=f"tests/gates/test_scenes.py::{matched[0]}"
        a=[sys.executable,"-B","-m","pytest","-q","-p","no:cacheprovider","--tb=short",full]
        begin=time.monotonic()
        try:
            res=cmd(a,cwd=candidate,seconds=75)
            so, se=res.stdout,res.stderr
            (case_dir/(name+".stdout")).write_bytes(so)
            (case_dir/(name+".stderr")).write_bytes(se)
            record.update({"status":"CORROBORATED" if res.returncode==0 else "FAIL",
                "argv":a,"exit_code":res.returncode,"stdout_sha256":sha_bytes(so),
                "stderr_sha256":sha_bytes(se),"elapsed_sec":round(time.monotonic()-begin,3)})
        except subprocess.TimeoutExpired:
            record.update({"status":"FAIL","reason":"case_timeout_75s"})
    record["ended_at"]=utc()
    scene_rows.append(record)
    print(f"TA_SCENE_{num:02d}={record['status']}",flush=True)
ind_pass=sum(c["pass"] for c in independent)
rows_pass=sum(c["status"]=="CORROBORATED" for c in scene_rows)
failures=sum(not v["pass"] for v in assertions)
report={"kind":"TA_CHAT_GATES_99FD_INDEPENDENT_CONTROLLED_TEST",
        "reviewer":"TA-CHAT-REVIEWER-OCTO-20261101-01",
        "candidate_sha":TIP,"candidate_tree":TREE,"base_sha":BASE,"contract_sha256":CONTRACT,
        "env":facts,"preflight":assertions,
        "independent_function_probes":independent,
        "l1_disposable_git_real_drill":l1,
        "scenes_43":scene_rows,"scene_replay_correlated_count":rows_pass,
        "independent_probe_passed":ind_pass,"independent_probe_count":len(independent),
        "acceptance_ids_42":ACCEPT_IDS,
        "A2_real_principal_and_shared_write":"NOT_VERIFIED",
        "G1_authoritative_Ops_pin_mount":"NOT_VERIFIED (CI pin reconstructed from fixed Git and authenticated external checksum)",
        "independent_43_scene_verdicts":"NOT_ESTABLISHED_BY_BUILDER_CASE_REPLAY",
        "g4_pass":False,"runtime_pass":False,"ended_at":utc(),
        "status":"EVIDENCE_COVERAGE_ONLY" if rows_pass==43 and failures==0 and ind_pass==len(independent) else "PARTIAL_OR_FAIL"}
(out/"ta-gates-results.json").write_text(json.dumps(report,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
print("TA_GATES_RESULTS "+report["status"]+" scene_replayed="+str(rows_pass)+
      " independent="+str(ind_pass)+"/"+str(len(independent))+" l1="+l1["status"]+
      " G4_PASS=false",flush=True)
sys.exit(0 if report["status"]=="EVIDENCE_COVERAGE_ONLY" and l1["status"]=="PASS" else 2)
