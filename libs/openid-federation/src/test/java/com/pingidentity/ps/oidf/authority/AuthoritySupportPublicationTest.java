/*
 * The signer, the authority's entity id and the configuration builder are published in one write (plan item S-9).
 */
package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthoritySupportPublicationTest {

    private static final HostedEntitySigner SIGNER = entity -> {
        throw new IllegalStateException("not exercised in this test");
    };

    @BeforeEach
    @AfterEach
    void reset() {
        AuthoritySupport.resetForTests();
    }

    @Test
    void aConfigurationThatFailsPublishesNothing() {
        assertThrows(IllegalArgumentException.class, () -> AuthoritySupport.configureSigning(SIGNER, " "));
        assertThrows(NullPointerException.class, () -> AuthoritySupport.configureSigning(null, "https://as.example.com"));

        assertFalse(AuthoritySupport.isHostingConfigured());
        assertEquals(Optional.empty(), AuthoritySupport.authorityEntityIdIfConfigured());
        assertThrows(IllegalStateException.class, AuthoritySupport::hostedEntitySigner);

        // ...so a later attempt - the supervisor's retry - still configures it.
        AuthoritySupport.configureSigning(SIGNER, "https://as.example.com");
        assertTrue(AuthoritySupport.isHostingConfigured());
        assertEquals("https://as.example.com", AuthoritySupport.authorityEntityId());
    }

    @Test
    void aReaderNeverSeesHalfAConfiguredAuthority() throws Exception {
        // Readers spin while the authority is configured; whenever one sees it configured, every part of it is there.
        List<String> halves = new CopyOnWriteArrayList<>();
        for (int round = 0; round < 200; round++) {
            AuthoritySupport.resetForTests();
            CountDownLatch go = new CountDownLatch(1);
            List<Thread> readers = new ArrayList<>();
            for (int r = 0; r < 4; r++) {
                Thread reader = new Thread(() -> {
                    try {
                        go.await();
                        for (int spin = 0; spin < 100_000; spin++) {
                            Optional<String> id = AuthoritySupport.authorityEntityIdIfConfigured();
                            if (id.isPresent() || AuthoritySupport.isHostingConfigured()) {
                                // Seen as configured: the signer, the id and the builder must all be there.
                                assertNotNull(AuthoritySupport.hostedEntitySigner());
                                assertEquals("https://as.example.com", AuthoritySupport.authorityEntityId());
                                assertNotNull(AuthoritySupport.configurationBuilder());
                                return;
                            }
                        }
                    } catch (Throwable t) {
                        halves.add(String.valueOf(t));
                    }
                });
                reader.start();
                readers.add(reader);
            }
            go.countDown();
            AuthoritySupport.configureSigning(SIGNER, "https://as.example.com");
            for (Thread reader : readers) {
                reader.join(TimeUnit.SECONDS.toMillis(10));
            }
        }
        assertTrue(halves.isEmpty(), "a reader saw a half-configured authority: " + halves);
    }
}
