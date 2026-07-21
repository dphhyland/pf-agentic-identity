package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The consent fallback is lazy: the grant attributes are a second round trip to the grant
 * store, and once an authorization detail processor is deployed the native consent is
 * always present, so paying for that read on every request would be pure waste.
 *
 * <p>GrantView.from cannot be exercised with a real AccessGrant outside PingFederate --
 * constructing one reaches into the server's service locator -- so these cover the parts
 * that are reachable.
 */
class GrantViewFallbackTest {

    @Test
    void aNullGrantIsNullRegardlessOfAttributes() {
        AtomicInteger reads = new AtomicInteger();
        assertNull(GrantView.from(null, () -> {
            reads.incrementAndGet();
            return null;
        }));
        assertEquals(0, reads.get(), "a grant that does not exist must not trigger a store read");
    }

    @Test
    void unreadableAttributesAreTreatedAsNoConsentNotGuessed() {
        // Putting words in the user's mouth is worse than reporting no consent.
        assertEquals(0, GrantView.consentFromAttributes(null).size());
    }
}
