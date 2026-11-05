# IMPACT

Audit of tip `5ae0389b938f22cecc70853368b2f6614e04dbfd` tree. Successor replaces in-repo copies of the real read_thread bodies. `runtime_pass=false`. History was not rewritten.

Verdicts: REAL_PRIVATE = real service/history body at that blob. SYNTHETIC = already a TEST_ONLY vector. CLEAN = no real service body.

| path | blob sha | verdict | action |
|---|---|---|---|
| `.github/pull_request_template.md` | `d1a85988edcd01a4f221c0a8b3c5933b32e0c99b` | CLEAN | none |
| `.github/workflows/ci.yml` | `457c1e0ebf13f57125815a87ab0d1944082064a5` | CLEAN | none |
| `README.md` | `869612b6d9139a0db86aa0639e1ae054975c7a2e` | CLEAN | none |
| `SOURCE-IMPORT-MANIFEST-G2-S1.json` | `a251c01dad1cf2555470e4b0a25fad9c27903933` | CLEAN | none |
| `VERIFICATION-PACK-M0.md` | `619d333674a7de5fd4f5e4f2fdd26a5290f2ac5e` | CLEAN | none |
| `VERIFICATION-PACK-M1.md` | `e624a4cb5c15567fd5d981cbb024d5b8a0acb0a9` | CLEAN | none |
| `VERIFICATION-PACK-M2.md` | `29f301e01008267606b53c424ea44a60d685f37f` | CLEAN | none |
| `docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json` | `513cee0eb5e6ff262e6890c03e2fcf2f6a585402` | CLEAN | none |
| `docs/spec/g2-s1/SPEC-SOURCE-MANIFEST.json` | `6716a98a7ae4f3eab79fddb61195a66b5d4854cd` | CLEAN | none |
| `docs/spec/g2-s1/T-00A-MATCH.md` | `d9beb7d46e758c50f87a0a49147ee50c9e8435c0` | CLEAN | none |
| `docs/spec/g2-s1/T-00A-T01-RECEIPT.md` | `08a8471ca3923f7a641037181ffe1f5e5e25341a` | CLEAN | none |
| `docs/spec/g2-s1/T-01-SPEC-ENVELOPE-ROUTER.md` | `e98b7613b30379cf8cb795070c5112f9419278db` | CLEAN | none |
| `docs/spec/g2-s1/recompute_inputs_hash.py` | `29dc2aae04c8da62d731ae7fa4455fbe210959cf` | CLEAN | none |
| `octo/__init__.py` | `6dc0d07135b18a00daab712b540622a8a803ce19` | CLEAN | none |
| `octo/backup.py` | `6b90d8b26e489e6901d346277a5e3ec89dfccd5a` | CLEAN | none |
| `octo/candidate.py` | `2453dec9162334ef1322cccd68cb74dc4ac10cc4` | CLEAN | none |
| `octo/closing.py` | `33441f99b49c532ccfeb0bfa11f2b3bb9597f7d3` | CLEAN | none |
| `octo/envelope.py` | `77fc599bf11dc17bd9e8622c3982d1bd28880605` | CLEAN | none |
| `octo/fixtures/grant-template.json` | `17c9412c4aa69e27d7762b6410721dbaad139989` | CLEAN | none |
| `octo/g3_review.py` | `8acc25de50ffded0920afbe6e446089fe24ab05b` | CLEAN | none |
| `octo/gateway.py` | `235faa06e392c7665132e77241626a1b4b881061` | CLEAN | none |
| `octo/governor.py` | `de288411af883f053a09f536c15b5b55aa18f205` | CLEAN | none |
| `octo/grant.py` | `16811f902934fcd201e878cb9cbf7a63ad247d52` | CLEAN | none |
| `octo/isolation_runner.py` | `2c46dc773c361964e2648ef75b6b2de6a9df38d0` | CLEAN | none |
| `octo/journal.py` | `c28bac8e5a3e006c6fbaddeee13b23d4ab82811e` | CLEAN | none |
| `octo/models.py` | `b0dc04acb91c6e98c27b2e40068fdcd2bb34e918` | CLEAN | none |
| `octo/n9.py` | `567f9b980fb91804690c530fcf98c5a4a124f3b5` | CLEAN | none |
| `octo/netguard.py` | `11976e62523d6cff437e510552df44ca840b8c2f` | CLEAN | none |
| `octo/nodes.py` | `3d954a6ccd46dc430daf62a6eae6272d3e0a610b` | CLEAN | none |
| `octo/objects.py` | `a8a52788e66250a4e94e3d2fce65b167bc00cc12` | CLEAN | none |
| `octo/router.py` | `834f36bc0d8f2ba65fdedc0d9f26c01a6f419da0` | CLEAN | none |
| `octo/schemas/node-envelope.schema.json` | `dee261d24e4b4400e62e280789d84c7ade149272` | CLEAN | none |
| `octo/scope/SCOPE-MANIFEST.json` | `817e0fa93defe7eb8d2c2888be81087cada9d219` | CLEAN | none |
| `octo/scope_metadata.py` | `244d80bec5aa49a83badf588571fe0b52893f415` | CLEAN | none |
| `octo/standard.py` | `4252c39a017e7e9b080bf7bf0b6e4dd141fd0020` | CLEAN | none |
| `octo/trusted_original.py` | `95991689a1eadce1fdaee646d23ce40c764d7375` | CLEAN | none |
| `requirements.txt` | `aae2311c6b2dd45d44cb99a9d338363a465ca6df` | CLEAN | none |
| `scripts/g3_review_entry` | `e2c6a0c4970522646ce038991de6c1cfcd25f63e` | CLEAN | none |
| `tests/fixtures/g2s1/isolation-policy.json` | `95275af7c61fb40894d03493286b9369cbfc4101` | CLEAN | none |
| `tests/fixtures/g2s1/runtime-artifact-inventory.json` | `c1408072b7d7e2a3e1974fbeb1d5c2978863439f` | CLEAN | none |
| `tests/fixtures/g2s1/templates/grant-template.json` | `17c9412c4aa69e27d7762b6410721dbaad139989` | CLEAN | none |
| `tests/fixtures/g2s1/templates/marker.txt` | `9bbf27bbe5bad424ebf6337c14e6aa99b5a7e66f` | CLEAN | none |
| `tests/fixtures/n11-fenced/test-only-escaped-blocked.txt` | `6a3a6e29b1a7620f7f88163edae578a4535aea75` | SYNTHETIC | kept; already a TEST_ONLY fence vector |
| `tests/fixtures/n11-fenced/test-only-fenced-blocked.txt` | `58e9aa9a84d2f210adcee2fc91666745d394a5a6` | SYNTHETIC | kept; already a TEST_ONLY fence vector |
| `tests/fixtures/n11-read-thread/agent-message.exact.nolf` | `77c1e61b64d5352ea7dd2784b5a37addec38a2d9` | REAL_PRIVATE | replaced with synthetic TEST_ONLY text; old bytes remain reachable on parent 5ae0389b |
| `tests/fixtures/n11-read-thread/service-response.exact.nolf` | `a08e90613a777b283814d991ebcffa6c70c33a8b` | REAL_PRIVATE | replaced with synthetic TEST_ONLY read_thread shape; old bytes remain reachable on parent 5ae0389b |
| `tests/test_backup.py` | `5ac1f8d7abc472f8f1fcf304c2351bca6f061603` | CLEAN | none |
| `tests/test_candidate.py` | `4cb4eaf75f4247894f42daba3290fe55ea878c3a` | CLEAN | none |
| `tests/test_closing.py` | `b488a595e7c3e7a7b5fda8606e7e3eca7c66de88` | CLEAN | none |
| `tests/test_envelope.py` | `0d094d5c9cbf35f8180716880fad3ee400abfbff` | CLEAN | none |
| `tests/test_g3_fence_consume.py` | `b6aeb9bf96d3cf3218c46b23459c9423d954e1da` | CLEAN | none |
| `tests/test_g3_review.py` | `6b4d6151db53ee789b310b14463c4ee41973667b` | CLEAN | none |
| `tests/test_gateway.py` | `dcf734cff8b3d6189d45fea7f836716d48d67f7f` | CLEAN | none |
| `tests/test_grant.py` | `8389be6ca449f94abcb76e83f4cf9849624b3ce6` | CLEAN | none |
| `tests/test_io_fixtures.py` | `3ea16ee9e13d751b86c3cd9ae6a9f68a16e071fc` | CLEAN | none |
| `tests/test_isolation_runner.py` | `53598067cb91e64a408fef194bc6829e6252ef2c` | CLEAN | none |
| `tests/test_models.py` | `0bf6fe7f2338b6d95524b997765dabfbf085a95d` | CLEAN | none |
| `tests/test_n11_contract.py` | `5b5613b9fc58490450f822b93c8928668c9c391b` | CLEAN | none |
| `tests/test_n11_phase_b.py` | `bcabd6d8b28f78c520c8358a9aaed05dfbb6998a` | CLEAN | updated fixture hash and id expectations only; file did not contain the service body |
| `tests/test_n1_bad_input.py` | `d478ddae967c3318c687ccf6d42efe93b2174756` | CLEAN | none |
| `tests/test_n2_source.py` | `9971e139a775b8a31b1797a12312c6930b7958eb` | CLEAN | none |
| `tests/test_n5_stale.py` | `8aa4f839451f2a0135607cda56fb24fec4b6adbd` | CLEAN | none |
| `tests/test_n8_node_ac.py` | `db5ee86ca62f29d41bc6f0d2f4963450a6f4445d` | CLEAN | none |
| `tests/test_netguard.py` | `b108a1240163d42a41274027565bf59370ecbc31` | CLEAN | none |
| `tests/test_nodes.py` | `dc97582006454011b0a5edd4813bd1b7a56dbb1f` | CLEAN | none |
| `tests/test_router.py` | `8eba1b5fcf85ae2ca7e6d1f62cbd0d4ad6131f4f` | CLEAN | none |
| `tests/test_scope_metadata.py` | `8c7bf0e9e18dd2ef94a17bc2d515e897d9c98d5f` | CLEAN | none |
| `tests/test_trusted_original.py` | `ea27becf1a1313860ce22c8dbc18e5770bb22fc6` | CLEAN | none |

Blobs audited: 68.

Successor content sha256, not the parent blobs:

- `tests/fixtures/n11-read-thread/agent-message.exact.nolf` `fa3a823d8751a3abe31d483c572a7a306ad422b509bf5227f9fbf4dd0ddd4275` (61 bytes) SYNTHETIC. Not `bd2ff242bbff293779b482ed0a90640174560b28783b919e1c90f377ea5edeb0`.
- `tests/fixtures/n11-read-thread/service-response.exact.nolf` `5e3183c5285b8968a91264259fd61194e468c7010f210f5691aeb724b478e6d0` (485 bytes) SYNTHETIC. Not `cf3deb9e7d709b4b1c43468dbf1af0f4bb559e6e29c165fae2b58292ed0f39eb`.

`octo/closing.py` keeps the owner appointment thread id constant. That constant is not a service-response body and was not changed.

No journal-under-control-plane reject was added. Consume path formula is unchanged.
