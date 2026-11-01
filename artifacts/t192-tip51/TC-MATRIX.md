# TC-MATRIX · TB t192 tip51 independent evidence

Candidate `51a23ccd4f9efe7bafc759703997b01eccb04e13` tree `babde0c3ac257f5d8ec1a2ec046e316f8a04ac5c` parent `875836d57cf1f557bb71fc094025f72a084f44dc`.

Row verdicts are evidence labels. They are not `runtime_pass`, not `verification_pass`, and not a product PASS.
`MATCH` means the observed value met that row's frozen expectation.
`PASS` on an A2 row means that mechanism check held on a tester-made store.
`PASS_EVIDENCE` on NA-RO-03/04 means the hash-matched tip51 Ops bed, not a re-run on this VM and not a GAP close.
`CAPABILITY_GAP` is not a pass. pytest `xfail` is not a pass.

Probe status: `T192_TIP51_EVIDENCED_PARTIAL`. Counts: `{"MATCH": 71, "PASS_EVIDENCE": 2, "CLEARED": 1, "OPEN": 9, "CAPABILITY_GAP": 1, "PASS": 6, "CONTEXT": 1}`.

| ID | Group | Verdict | Expected | Actual |
|---|---|---|---|---|
| `PIN-HEAD-TREE-PARENT` | pin | MATCH | HEAD 51a23ccd… tree babde0c3… parent 875836d5… | HEAD=51a23ccd4f9efe7bafc759703997b01eccb04e13 tree=babde0c3ac257f5d8ec1a2ec046e316f8a04ac5c parent=875836d57cf1f557bb71fc094025f72a084f44dc |
| `NA-RO-03` | t187 | PASS_EVIDENCE | tip51 Ops bwrap --ro-bind: index open/replace/unlink/rename all OSError; sha unchanged; not tip047 | ops=open_w:EROFS/30,os.replace:EXDEV/18,os.unlink:EROFS/30,os.rename:EROFS/30 sha_unchanged=True ST_RDONLY=True replace_EXDEV=True reexecuted_here=false box_mount_present=False |
| `NA-RO-04` | t187 | PASS_EVIDENCE | same ro-bind writes against fixture original all OSError; sha unchanged; fixture not a formal original | ops=open_w:EROFS/30,os.replace:EXDEV/18,os.unlink:EROFS/30,os.rename:EROFS/30 fixture_registered_in_production=False sha_before=8ed407dc826fc62b23cbfce83d5c1839c2a69e20a322d3d294fcd96efaca73f8 |
| `OPS-TIP51-PIN` | ops | MATCH | proof and receipt pin this HEAD/tree/parent and intake b98f5a5c; hashes match the stated digests | hash_match=True pin_match=True proof=21700f5fa8851659654b740976043b13023eea836569a2dd5f1a550337cf305f md=0c33e6ced12fb9bb380091266994f571d11a6d984123ddf59395dda054743721 json=dbb67fb8213f6c217bef6dec1e8cf012d7ab16ede305095974e10707735e8607 |
| `WAITING_OPS_TIP51` | ops | CLEARED | cleared because tip51 Ops bed is hash-matched; tip047 bed is not a substitute and was not used | CLEARED |
| `NA-RO-01` | t187 | MATCH | chmod a-w without ro-bind is RO_BIND_UNPROVEN and is not hard-isolation PASS | ro_bind_assessment(chmod)=RO_BIND_UNPROVEN os.access_W_OK=False local_ST_RDONLY=False |
| `NA-RO-02` | t187 | MATCH | os.access W_OK false alone is RO_BIND_UNPROVEN | assessment=RO_BIND_UNPROVEN access_false=True |
| `RO-BIND-ASSESSMENT-CODE` | ops | OPEN | candidate ro_bind_assessment does not consume the Ops proof and does not close GAP-04 | assessment_of_bwrap_dict=RO_BIND_UNPROVEN |
| `NA-IS-01` | t187 | MATCH | Rejected/Empty ISSUER_SESSION_COLLISION; content not returned | Rejected ISSUER_SESSION_COLLISION |
| `NA-IS-02` | t187 | MATCH | Rejected/Empty ISSUER_MISMATCH; content not returned | Rejected ISSUER_MISMATCH |
| `NA-IS-03` | t187 | MATCH | Rejected/Empty ISSUER_MISMATCH; content not returned | Rejected ISSUER_MISMATCH |
| `NA-IS-04` | t187 | MATCH | correct issuer and session: shape may pass; formal trust is not PASS | consume=Found test_only=True kind=TEST_FIXTURE verdict=PASS n11=status=BLOCKED verdict=BLOCKED note=TEST_FIXTURE_ONLY runtime_pass_field=False |
| `NA-TF-01` | t187 | MATCH | TEST_FIXTURE hit is BLOCKED + TEST_FIXTURE_ONLY and is not a formal original | status=BLOCKED verdict=BLOCKED note=TEST_FIXTURE_ONLY runtime_pass_field=False |
| `NA-RG-01` | t187 | MATCH | registry.json symlink to outside is PATH_ESCAPE or ROOT_UNAVAILABLE and yields no content | Empty PATH_ESCAPE |
| `NA-RG-02` | t187 | MATCH | absolute path, .., and an intermediate symlink are PATH_ESCAPE and yield no content | dotdot=Rejected PATH_ESCAPE absolute=Rejected PATH_ESCAPE middle=Rejected PATH_ESCAPE |
| `NA-RG-03` | t187 | MATCH | open_registry reads registry.json through _read_confined; bare read_text is absent | confined=True naive_whole_file_scan=REGISTRY_INDEX_UNCONFINED |
| `NA-TF-02` | t187 | MATCH | empty registry is EMPTY_REGISTRY and N11 BLOCKED, not PASS | open=ReadOnlyRegistry:{} consume=Empty EMPTY_REGISTRY n11=status=BLOCKED verdict=BLOCKED note=EMPTY_REGISTRY no trusted reviewer registration runtime_pass_field=False |
| `N11-TO-01b` | n11 | MATCH | unconfigured root is BLOCKED ROOT_UNAVAILABLE | status=BLOCKED verdict=BLOCKED note=ROOT_UNAVAILABLE runtime_pass_field=False |
| `N11-TO-01b-writable` | n11 | MATCH | a writable root is ROOT_UNAVAILABLE and does not return the file body | Empty ROOT_UNAVAILABLE |
| `N11-ROOT-IN-CANDIDATE` | n11 | MATCH | a root inside the candidate tree is ROOT_UNAVAILABLE | Empty ROOT_UNAVAILABLE |
| `NA-TF-03` | t187 | MATCH | forged REVIEW_RECEIPT / nonempty string is EVIDENCE_UNVERIFIED or BLOCKED and is not formal trust | status=BLOCKED verdict=BLOCKED note=ROOT_UNAVAILABLE runtime_pass_field=False |
| `SOURCE-EVIDENCE-NONEMPTY` | t187 | MATCH | nonempty source_evidence on a REVIEW_RECEIPT is not independent verification | Rejected EVIDENCE_UNVERIFIED |
| `N11-FORMAL-OK` | n11 | OPEN | a real verified REVIEW_RECEIPT PASS is not available; GAP-01 and GAP-03 stay OPEN | Rejected EVIDENCE_UNVERIFIED |
| `N11-TO-06-route` | n11 | MATCH | changed route is TUPLE_MISMATCH | Rejected TUPLE_MISMATCH |
| `N11-TO-06f-short` | n11 | MATCH | short SHA does not normalize to a tuple and does not hit | Rejected TUPLE_MISMATCH |
| `N11-TO-06f-upper` | n11 | MATCH | uppercase hex normalizes and can hit the TEST_FIXTURE row; still test_only | Found test_only=True kind=TEST_FIXTURE verdict=PASS |
| `N11-TO-09` | n11 | MATCH | bytes_sha256 in the fixture set is FIXTURE_LOOP | Rejected FIXTURE_LOOP |
| `N11-TO-11` | n11 | MATCH | changed raw bytes are HASH_MISMATCH | Rejected HASH_MISMATCH |
| `N11-TO-14` | n11 | MATCH | two records for one tuple are AMBIGUOUS | Rejected AMBIGUOUS |
| `N11-TO-08` | n11 | MATCH | consuming a TEST_FIXTURE does not change closing.py; this is not a real PASS | sha_before=4578e7b3bfbcae3cae4e99fe5e9a98752b84afa5b8e9b0705bddfddd9599931e sha_after=4578e7b3bfbcae3cae4e99fe5e9a98752b84afa5b8e9b0705bddfddd9599931e |
| `N11-TO-02` | n11 | MATCH | self-written file plus public reviewer id is BLOCKED | status=BLOCKED verdict=BLOCKED note=ROOT_UNAVAILABLE runtime_pass_field=False |
| `N11-TO-03` | n11 | MATCH | builder_signed is BLOCKED BUILDER_PASS_FORBIDDEN | status=BLOCKED verdict=BLOCKED note=BUILDER_PASS_FORBIDDEN runtime_pass_field=False |
| `N11-TO-04` | n11 | MATCH | candidate self-report is BLOCKED | status=BLOCKED verdict=BLOCKED note=candidate self-report is not a TA reviewer receipt runtime_pass_field=False |
| `N11-TO-05` | n11 | MATCH | wrong issuer is BLOCKED forged | status=BLOCKED verdict=BLOCKED note=forged issuer runtime_pass_field=False |
| `DOD-A-UNTRUSTED-REVISE` | DoD-A | MATCH | an untrusted REVISE dict is not a formal opinion and is not raised to PASS | status=BLOCKED verdict=BLOCKED note=ROOT_UNAVAILABLE runtime_pass_field=False |
| `DOD-A-UNTRUSTED-BLOCKED` | DoD-A | MATCH | an untrusted BLOCKED dict is not raised to PASS | status=BLOCKED verdict=BLOCKED note=ROOT_UNAVAILABLE runtime_pass_field=False |
| `DOD-A-EMPTY-PROOF` | DoD-A | MATCH | sha-only empty proof is BLOCKED | status=BLOCKED verdict=BLOCKED note=ROOT_UNAVAILABLE runtime_pass_field=False |
| `DOD-A-BUILDER-FLAG` | DoD-A | MATCH | builder_claims_pass raises BUILDER_PASS_FORBIDDEN | BUILDER_PASS_FORBIDDEN |
| `N11-TO-15` | n11 | MATCH | with no registry, _verified_original is None; with a TEST_FIXTURE registry it is not None and stays test_only | no_registry=None with_fixture=Found test_only=True kind=TEST_FIXTURE verdict=PASS |
| `N11-TO-16` | n11 | OPEN | a non-fixture FAIL verdict cannot become a formal PASS while GAP-03 is open | Rejected EVIDENCE_UNVERIFIED |
| `N11-TO-10` | n11 | MATCH | candidate registration_id / path does not grant trust; fixture hit stays TEST_FIXTURE_ONLY | status=BLOCKED verdict=BLOCKED note=TEST_FIXTURE_ONLY runtime_pass_field=False |
| `DOD-B-N11-OVERALL` | DoD-B | MATCH | no trusted original: N11 BLOCKED and run_standard body status is not OK | body=BLOCKED n11=BLOCKED/BLOCKED ids=['N1', 'N2', 'N3', 'N4', 'N5', 'N8', 'N9', 'N10', 'N11', 'N12', 'N13'] |
| `DOD-B-N10-PACK` | DoD-B | MATCH | N10 context_pack is that run's N2 seven-field pack | equal=True keys=['assembled_at', 'current_decisions', 'intent_id', 'key_evidence', 'open_states', 'prohibitions', 'sources'] |
| `DOD-B-INTENT` | DoD-B | MATCH | N1 and N2 share one intent id on this run | n1=intent-PRODUCT-BUILD-2026-11-01-G2-S1-TB-01 n2=intent-PRODUCT-BUILD-2026-11-01-G2-S1-TB-01 |
| `DOD-B-N1-STOP` | DoD-B | MATCH | N1 NEEDS_CLARIFICATION stops the prefix | status=NEEDS_CLARIFICATION ids=['N1'] |
| `DOD-B-FOREIGN-INTENT` | DoD-B | MATCH | a foreign N2 intent stops the chain | status=BLOCKED ids=['N1'] |
| `DOD-B-N2-PARTIAL-READONLY` | DoD-B | MATCH | N2 PARTIAL on internal_readonly may continue and the body stays PARTIAL | status=PARTIAL n2=PARTIAL readonly=True ids=['N1', 'N2', 'N3', 'N4', 'N5', 'N8'] |
| `DOD-B-PARTIAL-CONSEQUENTIAL` | DoD-B | MATCH | a non-readonly action does not run the prefix; the PARTIAL guard rejects a consequential action | route_status=BLOCKED ids=[] guard_raised=True |
| `DOD-B-N3-STOP` | DoD-B | MATCH | N3 still_worth_it false stops before N4 and body is not OK | status=BLOCKED ids=['N1', 'N2', 'N3'] worth=False |
| `DOD-B-N5-STOP` | DoD-B | MATCH | N5 with an unadjudicated claim is PARTIAL and stops before N8 | status=PARTIAL ids=['N1', 'N2', 'N3', 'N4', 'N5'] fact=CLAIM |
| `DOD-B-N8-STOP` | DoD-B | MATCH | N8 'works well' is NEEDS_CLARIFICATION and stops before N9 | status=NEEDS_CLARIFICATION ids=['N1', 'N2', 'N3', 'N4', 'N5', 'N8'] |
| `DOD-V11-OVERALL` | DoD-B | MATCH | N2 PARTIAL may continue read-only; N11 BLOCKED makes run_standard overall not OK | body=BLOCKED n2=PARTIAL n11=BLOCKED |
| `DOD-C-OBJECTS` | DoD-C | MATCH | written objects are only Decision, Evidence, Receipt; failure row is a Receipt; path opens from store_root; sha matches | objects=['Receipt', 'Decision', 'Decision', 'Evidence', 'Receipt'] paths_open=[True, True, True, True, True] sha_ok=True link=capture/Decision-d0.json link_ok=True |
| `DOD-C-IDEMPOTENT` | DoD-C | MATCH | same Receipt content is returned again and does not raise SUPERSEDE_OVERWRITE | second_sha=ccb6fdb3f49b87cd7d5c38885e01efaf6ef85b2cdd11d0d2443fae5070e6ad90 same_bytes=True |
| `DOD-C-CONFLICT` | DoD-C | MATCH | conflicting content raises CONTENT_CONFLICT and leaves the old bytes in place | CONTENT_CONFLICT:capture/Receipt-r1.json bytes_unchanged=True |
| `DOD-H1` | DoD-D4 | MATCH | N12 writeback failure makes N13 writeback_state FAILED and body is not OK | n12=BLOCKED writeback=FAILED body=BLOCKED helper=FAILED |
| `DOD-H2` | DoD-D4 | MATCH | N12 success makes writeback_state OK legally while N11 stays BLOCKED | writeback=OK n12=OK n11=BLOCKED body=BLOCKED |
| `DOD-H3` | DoD-D4 | MATCH | handoff follows the N11 condition: missing reviewer is NOT_READY; a PASS envelope is READY; a BLOCKED/REVISE envelope is NOT_READY | ready=READY blocked=NOT_READY revise=NOT_READY run_standard=NOT_READY wired=True |
| `DOD-H-NO-CONSTANT-ASSIGN` | DoD-D4 | MATCH | run_standard does not assign writeback_state or handoff_state as a bare constant | bare_constant_assignment_present=False |
| `DOD-D4-SAME` | DoD-D4 | MATCH | same store, intent, and blocker: second call and a new process do not notify again | first=True second=False restart={'notify_once': False} |
| `DOD-D4-CHANGE` | DoD-D4 | MATCH | a blocker change notifies again | changed=True |
| `DOD-D4-INTENT` | DoD-D4 | MATCH | a different intent is not suppressed by the same blocker label | other_intent=True |
| `DOD-D4-OTHER-STORE` | DoD-D4 | MATCH | another store still notifies; two stores are not used as the dedup proof | other_store=True proof_is_same_store_second=False |
| `DOD-D4-NO-GLOBAL-SET` | DoD-D4 | MATCH | no module-level mutable set is the dedup bucket; shape sets are not that bucket | dedup_sets=[] schema_sets=['N11_KEYS', 'N12_KEYS', 'N13_KEYS'] frozenset_constants=['WRITTEN_OBJECTS', '_READY'] |
| `DOD-D-LINKS` | DoD-D | MATCH | evidence_links are openable capture paths or recomputable sha256 pointers, not status strings | links=['capture/Receipt-R-5f8c75f37ab242a19b15df0ec5b59bf7.json', 'sha256:819e9b6c45deaf2d614159386e08b7589d1b3a40cd6fa52cc564aeddb0cb1cf4', 'sha256:f87015b551cb92b8fcc80a60a4007d5611585344390d095bf75ae97b58ef1ab6', 'sha256:e09392bdd4409c736c4611675295c92a8ba3378383672c382dae2... |
| `DOD-D-WRITEBACK-SPLIT` | DoD-D | MATCH | writeback FAILED is not reported as SUCCEEDED or envelope OK | state=BLOCKED status=BLOCKED owner=builder next=repair-writeback |
| `DOD-D4-RUN-STANDARD` | DoD-D4 | MATCH | a second run_standard on the same store and intent suppresses the same blocker | first=True second=False blocker={'outcome': 'SUCCEEDED', 'verify_state': 'BLOCKED', 'writeback_state': 'OK', 'handoff_state': 'NOT_READY'} |
| `DOD-E-N9-DIGEST` | DoD-E | MATCH | a mismatched request_digest is DENY, writes a receipt file, and carries this request's grant draft | status=AUTHORIZATION_REQUIRED verdict=DENY receipts=1 draft_has_digest=True |
| `DOD-E-N9-NO-GRANT` | DoD-E | MATCH | no valid grant is DENY / AUTHORIZATION_REQUIRED with a draft and does not authorize | status=AUTHORIZATION_REQUIRED reason=GRANT_FILE_INVALID_OR_MISSING; grant_scope_draft action=internal_readonly actor=actor-a resource=/tmp/t192-work/n9/readable.txt intent=intent-PRODUCT-BUILD-2026-11-01-G2-S1-TB-01 d |
| `DOD-E-N5-UNREADABLE` | DoD-E | MATCH | a FACT whose file does not open is not left as FACT and is SOURCE_UNAVAILABLE | status=SOURCE_UNAVAILABLE fact={'claim': 'readable-fact', 'verdict': 'CLAIM', 'evidence_ref': '/tmp/t192-work/no-such-fact.txt', 'freshness': 'fresh'} gaps=['SOURCE_UNAVAILABLE'] |
| `DOD-E-N5-FACT` | DoD-E | MATCH | a FACT with a readable fresh file stays FACT | status=OK verdict=FACT |
| `DOD-E-N5-STALE` | DoD-E | MATCH | stale evidence stays STALE, writes a recollect marker, and the label alone is not the whole result | verdict=STALE status=PARTIAL label=True marker_exists=True marker_sha=76f6219a71828272c5088b585a4eca709515569594ee5d416aa7acbdc1a6fe24 |
| `N10-FIXED` | N10 | MATCH | fixed file bytes: two executions share one SUCCEEDED effect and the same content summary | first=SUCCEEDED second=SUCCEEDED same_receipt=True dispatch=1 sha=023ec624a31bb54fb5018eabfb1e72d2583177e19de5e8287809d7ee5b4188f6 summary={'bytes': 11, 'sha256': '023ec624a31bb54fb5018eabfb1e72d2583177e19de5e8287809d7ee5b4188f6'} |
| `N10-CHANGED` | N10 | MATCH | changed file bytes change the content summary | state=SUCCEEDED sha=96ff299e658dcedeaf95f703d5493ef534cfaa5e1bc4db43d4cd74a47cf8787d expected=96ff299e658dcedeaf95f703d5493ef534cfaa5e1bc4db43d4cd74a47cf8787d |
| `N10-NO-AUTH` | N10 | MATCH | no grant does not SUCCEEDED and does not dispatch | status=AUTHORIZATION_REQUIRED output=None dispatch=0 effects=0 |
| `BWRAP-LOCAL` | bwrap | CAPABILITY_GAP | if bwrap is absent, CAPABILITY_GAP with the runner record; xfail is not a pass | which=None runner={'runtime_pass': False, 'capability': 'CAPABILITY_GAP', 'returncode': None, 'argv': ['bwrap', '--die-with-parent', '--new-session', '--unshare-net', '--unshare-pid', '--as-pid-1', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/... |
| `A2-THREE-COMPONENT` | A2 | PASS | template, isolation, and runtime digests recompute; fixture_digest is the digest of those three | runtime_code=a7a16e2615b55f7b52d2318fcc1d137d7b417bdf24d16e21d00addee96693ffa runtime_indep=a7a16e2615b55f7b52d2318fcc1d137d7b417bdf24d16e21d00addee96693ffa fixture_code=f38768ac593258c16471e348ab5cf72a927b37ccc231048bc4d17105a53ce5cb fixture_indep=f38768ac593258c16471e348ab5c... |
| `A2-BYTE` | A2 | PASS | one flipped byte invalidates the old binding; re-registering changes runtime and fixture digests only | old_call=CONTENT_SHA_MISMATCH runtime_changed=True fixture_changed=True template_same=True isolation_same=True |
| `A2-FAIL-CLOSED` | A2 | PASS | missing file, wrong candidate, snapshot kind, empty items, in-repo schema, and .. are rejected | missing=ARTIFACT_MISSING candidate=CANDIDATE_SHA_MISMATCH cycle=CYCLE_INPUT_FORBIDDEN empty=EXTERNAL_MANIFEST_EMPTY schema=RUNTIME_SCHEMA_NOT_EVIDENCE escape=PATH_ESCAPE |
| `A2-PATH-NORMALIZE` | A2 | PASS | relative and absolute manifest paths normalize to one runtime digest | relative=a7a16e2615b55f7b52d2318fcc1d137d7b417bdf24d16e21d00addee96693ffa absolute=a7a16e2615b55f7b52d2318fcc1d137d7b417bdf24d16e21d00addee96693ffa |
| `A2-HANDOFF-BINDING` | A2 | PASS | handoff_binding returns RECEIVED with runtime_pass false and does not write a snapshot | decision=RECEIVED product_pass=False runtime_pass=False wrote_new=False repo_snapshots=[] |
| `A2-REVIEW-REFUSES-PASS` | A2 | PASS | review_entry does not issue PASS | PermissionError: builder self-sign blocked |
| `A2-TIP51-INVENTORY` | A2 | OPEN | an Ops external Grant/request/Receipt/log inventory pinned to tip51 | no such manifest is on this VM; the ro-bind proof is not an A24 inventory |
| `A2-HANDOFF-SNAPSHOT` | A2 | OPEN | a sealed handoff_snapshot for tip51 | function does not write one; none is in the candidate tree |
| `GAP-01` | gap | OPEN | remain OPEN | no production reviewer record; empty registry |
| `GAP-02` | gap | OPEN | remain OPEN | no writer, key, or channel was created |
| `GAP-03` | gap | OPEN | remain OPEN | source_evidence shape is not independent verification |
| `GAP-04` | gap | OPEN | remain OPEN | Ops measured fixture physical RO; status still OPEN |
| `NA-GAP-01` | t187 | MATCH | this handback must not claim N11 complete or GAP-01..04 closed | not claimed; gaps recorded OPEN; tip047 seal not applied |
| `PYTEST-CONTEXT` | context | CONTEXT | pytest exit and xfail are context only and are not acceptance | exit=0 tail=['........................................................................ [ 55%]', '....x.....................................................               [100%]', '=========================== short test summary info ============================', 'XFAIL tests/t... |
| `PRODUCT-TREE-UNTOUCHED` | custody | MATCH | git status --short empty after the probe | (clean) |

Full actual strings: `logs/cases.json`.
