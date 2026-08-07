package com.pingidentity.ps.oidf.agent;

class InMemoryAgentRegistryTest extends AgentRegistryContract {

    @Override
    protected AgentRegistry newRegistry() {
        return new InMemoryAgentRegistry();
    }
}
