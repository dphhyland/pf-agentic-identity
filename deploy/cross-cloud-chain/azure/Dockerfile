# Layer on the Azure demo workload image (../../azure-aks-demo/workload), which is already
# linux/amd64 with cryptography installed — so this build is a COPY rather than a cross-architecture
# pip install (which takes many minutes under emulation on an arm64 laptop). Same reasoning as the
# other chain Dockerfiles; do not "simplify" it to python:slim.
#
# BASE_IMAGE is an ARG rather than hardcoded because, unlike the GKE/AWS legs, the Azure registry does
# not exist until azure/bootstrap.sh has run — there is no stable public tag to bake in yet. Pass it:
#   docker build --build-arg BASE_IMAGE=$ACR_LOGIN_SERVER/aks-workload:latest .
ARG BASE_IMAGE=aks-workload:latest
FROM ${BASE_IMAGE}
COPY agent_d.py /app/agent_d.py
WORKDIR /app
EXPOSE 8080
CMD ["python3", "agent_d.py"]
