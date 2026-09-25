# OpenID Federation on PingFederate

How this repo makes PingFederate a full member of an [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
federation - what it does, how, how to run it, and how we know it works.

Read in this order:

1. [Overview](overview.md) - what federation is, why agents need it, and the parts PingFederate plays.
2. [How it works](how-it-works.md) - chains, pinned anchors, policy and constraints, Trust Marks, registration and
   its lifetime, the policy engine, and what stops when.
3. [Configuration](configuration.md) - every setting, its default, and what happens when it's wrong.
4. [Operations](operations.md) - pinning and rolling anchor keys, running hosted agents, Trust Mark grants,
   reading the logs, wiring a policy engine.
5. [Conformance](conformance.md) - how it is tested: the OpenID Foundation suite's plans and our own tests.
6. [Limits](limits.md) - what it doesn't do, and where it is stricter than the specification.

[Glossary](glossary.md) for the words; [conformance matrix](conformance-matrix.md) for every requirement
implemented and the tests that pin it.

The code is in [`libs/openid-federation`](../../libs/openid-federation/README.md) (the federation itself, no
PingFederate code) and [`servlets/pf-integration`](../../servlets/pf-integration/README.md) (PingFederate's side).
