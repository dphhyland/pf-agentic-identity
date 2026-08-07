package com.pingidentity.ps.oidf.device;

/** The in-process registry, held to the shared contract. */
class InMemoryInstanceRegistryTest extends InstanceRegistryContract {

    @Override
    protected InstanceRegistry newRegistry() {
        return new InMemoryInstanceRegistry();
    }
}
