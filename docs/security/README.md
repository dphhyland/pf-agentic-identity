# Security documentation

How to report a vulnerability, which versions get fixes, and what is in scope: [SECURITY.md](../../SECURITY.md)
at the root of the repository.

What belongs here, from Phase 7 of the production programme (plan item D-6): the security model and threat
model - STRIDE per trust boundary, each threat's mitigation, the test or evidence behind it, the residual risk
and the finding ids - plus the PII policy. The internal red team takes its scope from that document.

Until then, the security posture is described where each component is: the "Security posture" section of
[libs/client-attestation](../../libs/client-attestation/README.md), the attestation design in
[docs/attestation-client-auth-design.md](../attestation-client-auth-design.md) and
[docs/client-attestation-architecture.md](../client-attestation-architecture.md), and the federation's
[limits](../federation/limits.md). The known defects and the assumptions nobody has verified are in the
[findings register](../findings/README.md).
