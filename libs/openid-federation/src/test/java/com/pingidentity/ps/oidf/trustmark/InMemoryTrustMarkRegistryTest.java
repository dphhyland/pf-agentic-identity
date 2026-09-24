package com.pingidentity.ps.oidf.trustmark;

/** The in-memory registry, held to the same contract as the durable one. */
class InMemoryTrustMarkRegistryTest extends TrustMarkRegistryContract {
    @Override
    protected TrustMarkRegistry newRegistry() {
        return new InMemoryTrustMarkRegistry(this.clock);
    }
}
