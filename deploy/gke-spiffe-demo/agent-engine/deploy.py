"""Deploy AttestedAgent to Vertex AI Agent Engine and run the chain once.

`agent.py` ships into the managed runtime via extra_packages, so the pickled instance resolves
`import agent` there (and does NOT drag the local vertexai SDK into the runtime image).

Usage: python3 deploy.py deploy <PROJECT_ID> <ATTESTER_BASE_URL>
       python3 deploy.py query|delete <PROJECT_ID> <RESOURCE_NAME>
"""
import json
import sys

import cloudpickle
import vertexai
from vertexai import agent_engines

import agent as agent_module
from agent import AttestedAgent

# Ship the agent module BY VALUE so the runtime never needs the local build context.
cloudpickle.register_pickle_by_value(agent_module)

LOCATION = "us-central1"


def main():
    mode, project = sys.argv[1], sys.argv[2]
    vertexai.init(project=project, location=LOCATION,
                  staging_bucket=f"gs://{project}-agent-staging")
    if mode == "deploy":
        attester_base = sys.argv[3]
        instance = AttestedAgent(
            attester_base=attester_base,
            client_id="demo-attest-agent-engine",
            client_secret="demo-secret-123",
            sa_email=f"agent-engine-demo@{project}.iam.gserviceaccount.com",
            pf_token_aud="https://localhost:9031",
        )
        remote = agent_engines.create(
            instance,
            display_name="attested-agent-demo",
            requirements=["cryptography>=42.0", "google-auth>=2.0", "cloudpickle"],
            extra_packages=["agent.py"],
            service_account=f"agent-engine-demo@{project}.iam.gserviceaccount.com",
        )
        print("resource:", remote.resource_name)
        out = remote.query(requested_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])
        print(json.dumps({k: out.get(k) for k in ("mint_status", "pf_status", "pf_body")}, indent=1))
    elif mode == "query":
        out = agent_engines.get(sys.argv[3]).query(requested_details=None)
        print(json.dumps({k: out.get(k) for k in ("mint_status", "pf_status", "pf_body")}, indent=1))
    elif mode == "delete":
        agent_engines.get(sys.argv[3]).delete(force=True)
        print("deleted")


if __name__ == "__main__":
    main()
