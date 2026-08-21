# Demos — where each one lives

This repo is the **capability**: the libs, servlets, plugins and services, plus the PF image build in
[`build/pingfederate/`](../build/pingfederate/README.md) that packages them. **It deploys nothing and
configures no PingFederate.** Every demo therefore lives in the repo that owns the environment it runs
in, along with the PF config that makes it work.

| Demo | Shows | Lives in |
|---|---|---|
| Staging environment | the AS + federation, live | [pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules/blob/main/docs/DEMOS.md) |
| Demo UI / harness | attestation client-auth, step by step, in a browser | [pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules/blob/main/docs/DEMOS.md) |
| SSF transmitter/receiver | CAEP/RISC SETs on real PF + Identity Object Model store | [pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules/blob/main/docs/DEMOS.md) (compose demo in `idp-pingfed-ssf-servelet`) |
| Cross-platform rigs | GKE / EKS / Azure workloads → one federation → cross-cloud `act` chain | **pf-agentic-identity-domain-authority** (private) |
| Device enrolment + phone simulator | App Attest + passkey + Secure Enclave enrolment, the CAEP loop | **pf-agentic-identity-domain-authority** (private) |
| RAR → PingAuthorize | RFC 9396 consent governed by a PDP, `requested ⊆ attested` | [idp-agentic-demo](https://github.com/dphhyland/idp-agentic-demo/blob/main/docs/DEMOS.md) |
| Grant Evaluation API | "is this grant still enough, right now?" | [idp-agentic-demo](https://github.com/dphhyland/idp-agentic-demo/blob/main/docs/DEMOS.md) |

## The sibling-checkout convention

Every consumer builds this repo's artifacts from a checkout beside its own, so clone them under one
parent and the relative paths in their scripts resolve:

```
Source/
  pf-agentic-identity/                    # this repo — the capability
  pf-oidf-modules/                        # OIDF + attestation demos, Railway project e02a8e2f
  idp-agentic-demo/                       # agentic banking demo, Railway project ac9af096
  pf-agentic-identity-domain-authority/   # cross-cloud rigs + phone-simulator (private)
```

To build what a demo consumes:

```sh
mvn -q -DskipTests package          # the module jars
build/pingfederate/stage-modules.sh # -> build/pingfederate/modules/ + MANIFEST
```

Then see [`build/pingfederate/README.md`](../build/pingfederate/README.md) for what each consumer
supplies on top — the config archive, its master key, and the demo attester trust.

---

Until 2026-08-21 this file carried all seven demos and asserted that "every deployable definition
stays **here** — no other repo may deploy `pingfederate-runtime`, `lighthouse`, `fedhost` or
`device-enrolment`." That was true for six days and wrong for the whole of them: the workflows here
had no Railway tokens and deployed nothing, ever, while `pf-oidf-modules` had been deploying those
services green since July. The demos went back to the repos that run them.
