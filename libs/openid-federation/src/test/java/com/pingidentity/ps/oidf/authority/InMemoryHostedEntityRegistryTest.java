package com.pingidentity.ps.oidf.authority;

class InMemoryHostedEntityRegistryTest extends HostedEntityRegistryContract {

    @Override
    protected HostedEntityRegistry newRegistry() {
        return new InMemoryHostedEntityRegistry();
    }
}
