/*
 * Lets a static (dev/demo) trust list and real OpenID Federation trust coexist on one PF instance
 * during a migration: attesters already onboarded to the static file keep resolving exactly as
 * before; anything not in that file falls through to federation.
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import org.jose4j.jwk.JsonWebKey;

/**
 * Composite {@link AttesterKeyResolver}: tries a {@link StaticAttesterKeyResolver} first, and for
 * any attester it doesn't have an entry for, falls through to a delegate (typically
 * {@link FederationAttesterKeyResolver}). This exists because {@code oidf.mock.attesters} is a
 * single JVM-wide switch — without this, turning it off to onboard one new federation-backed
 * client would also strip trust from every existing attester still registered only in the static
 * file. {@link StaticAttesterKeyResolver#isRegistered} decides the fallthrough (not exception
 * matching), so a genuine verification failure for a statically-registered attester still fails
 * closed instead of silently retrying against federation.
 */
public final class FallbackAttesterKeyResolver implements AttesterKeyResolver {
    private final StaticAttesterKeyResolver staticResolver;
    private final AttesterKeyResolver fallback;

    public FallbackAttesterKeyResolver(StaticAttesterKeyResolver staticResolver, AttesterKeyResolver fallback) {
        this.staticResolver = staticResolver;
        this.fallback = fallback;
    }

    @Override
    public List<JsonWebKey> resolve(String attesterIssuer, List<String> trustChainHeader) throws Exception {
        if (this.staticResolver.isRegistered(attesterIssuer)) {
            return this.staticResolver.resolve(attesterIssuer, trustChainHeader);
        }
        return this.fallback.resolve(attesterIssuer, trustChainHeader);
    }
}
