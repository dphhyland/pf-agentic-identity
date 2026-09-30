/*
 * The audit source's default vocabulary (plan item H-SSF-5): every PingFederate 13.1.3 audit event that maps to one
 * CAEP or RISC event without ambiguity, and only those; credential-change only with a CAEP credential_type.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.ssf.AuditEventMapper.Action;
import com.pingidentity.ps.oidf.ssf.AuditEventMapper.Rule;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuditVocabularyTest {

    private final AuditEventMapper mapper = new AuditEventMapper();

    /** The table in servlets/ssf/README.md ("The audit source"), row for row. */
    @Test
    void theDefaultsAreTheReadmeTable() {
        Map<String, Rule> expected = new LinkedHashMap<>();
        expected.put("SLO", new Rule(Action.SESSION_REVOKED, null, null));
        expected.put("SRI_REVOKED", new Rule(Action.SESSION_REVOKED, null, null));
        expected.put("AUTHN_SESSIONS_DELETED", new Rule(Action.SESSION_REVOKED, null, null));
        expected.put("AUTHN_SESSION_CREATED", new Rule(Action.SESSION_ESTABLISHED, null, null));
        expected.put("PWD_CHANGE", new Rule(Action.CREDENTIAL_CHANGE, "password", "update"));
        expected.put("ACCOUNT_DELETE", new Rule(Action.ACCOUNT_PURGED, null, null));
        assertEquals(expected, AuditEventMapper.DEFAULTS);
        assertEquals(List.copyOf(expected.keySet()), List.copyOf(AuditEventMapper.DEFAULTS.keySet()));
        assertEquals(expected, mapper.vocabulary());
    }

    /** The PingFederate 13.1.3 audit events the README table lists as not mapped, each for its reason. */
    @Test
    void theAmbiguousAndTheUnrelatedAreNotMapped() {
        for (String event : List.of("AUTHN_SOURCE_SESSION_DELETED", "SESSION_QUOTA_EXCEEDED", "AUTHN_SESSION_USED", "PWD_SET",
                "PROFILE_ATTRIBUTE_CHANGE", "REGISTER", "AUTHN_SOURCE_CONNECT", "AUTHN_SOURCE_DISCONNECT",
                "USER_KEY_AND_SRI_ASSOCIATED", "AUTHN_ATTEMPT", "AUTHN_REQUEST", "SSO", "OAuth", "PAR",
                "EMAIL_ADDRESS_VERIFY", "VERIFY_OTP", "SESSION_REVOKED", "SESSION_DELETED", "AUTHN_SESSION_DELETED")) {
            assertTrue(mapper.map(event, "success", "bob").isEmpty(), event);
        }
    }

    /** RISC 1.0 §2.2: account-purged "signals that the account identified by the subject has been permanently deleted". */
    @Test
    @Requirement("RISC §2.2")
    void aDeletedLocalIdentityIsAPurgedAccount() {
        assertEquals(Action.ACCOUNT_PURGED, mapper.map("ACCOUNT_DELETE", "success", "bob").orElseThrow().action());
    }

    /** CAEP 1.0 §3.6: session-established "signifies that the Transmitter has established a new session for the subject". */
    @Test
    @Requirement("CAEP §3.6")
    void aCreatedAuthenticationSessionIsAnEstablishedSession() {
        assertEquals(Action.SESSION_ESTABLISHED, mapper.map("AUTHN_SESSION_CREATED", "success", "bob").orElseThrow().action());
    }

    /**
     * CAEP 1.0 §3.3.1: {@code credential_type} "MUST be one of the following strings, or any other credential type
     * supported mutually by the Transmitter and the Receiver"; {@code change_type} "MUST be one of" create, revoke, update,
     * delete. A mapping names a registered type or none (never sent); an unregistered one is refused.
     */
    @Test
    @Requirement("CAEP §3.3.1")
    void aCredentialChangeNamesACaepCredentialType() {
        AuditEventMapper m = new AuditEventMapper("MFA_ADDED=credential-change:fido2-platform:create, X=credential-change");
        Rule added = m.map("MFA_ADDED", "success", "bob").orElseThrow().rule();
        assertEquals(new Rule(Action.CREDENTIAL_CHANGE, "fido2-platform", "create"), added);
        Rule untyped = m.map("X", "success", "bob").orElseThrow().rule();
        assertNull(untyped.credentialType(), "no type: mapped, and never sent as a guess");
        assertEquals("update", untyped.changeType());
        assertEquals(new Rule(Action.CREDENTIAL_CHANGE, "password", "update"), m.map("PWD_CHANGE", "success", "bob").orElseThrow().rule());

        assertThrows(IllegalArgumentException.class, () -> new AuditEventMapper("X=credential-change:credential"));
        assertThrows(IllegalArgumentException.class, () -> new AuditEventMapper("X=credential-change:password:rotate"));
        assertThrows(IllegalArgumentException.class, () -> new AuditEventMapper("X=credential-change:password:update:extra"));
        assertThrows(IllegalArgumentException.class, () -> new AuditEventMapper("X=session-revoked:now"));
    }

    @Test
    void everyActionHasASpelling() {
        AuditEventMapper m = new AuditEventMapper("A=session-revoked,B=session-established,C=account-disabled,"
                + "D=account-enabled,E=account-purged,F=Credential-Change:pin");
        assertEquals(Action.SESSION_REVOKED, m.map("A", "success", "s").orElseThrow().action());
        assertEquals(Action.SESSION_ESTABLISHED, m.map("B", "success", "s").orElseThrow().action());
        assertEquals(Action.ACCOUNT_DISABLED, m.map("C", "success", "s").orElseThrow().action());
        assertEquals(Action.ACCOUNT_ENABLED, m.map("D", "success", "s").orElseThrow().action());
        assertEquals(Action.ACCOUNT_PURGED, m.map("E", "success", "s").orElseThrow().action());
        assertEquals("pin", m.map("F", "success", "s").orElseThrow().rule().credentialType());
        assertThrows(NullPointerException.class, () -> new Rule(null, null, null));
        assertThrows(NullPointerException.class, () -> new AuditEventMapper.Mapped(null, "s", "e", null));
    }

    /** PingFederate's transactionid rides along as the SETs' txn; a blank one is none. */
    @Test
    void theTransactionIdIsCarried() {
        assertEquals("tx-1", mapper.map("SLO", "success", "bob", " tx-1 ").orElseThrow().transactionId());
        assertNull(mapper.map("SLO", "success", "bob", " ").orElseThrow().transactionId());
        assertNull(mapper.map("SLO", "success", "bob").orElseThrow().transactionId());
    }
}
