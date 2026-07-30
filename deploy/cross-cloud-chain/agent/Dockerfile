# Layer on the existing GKE demo agent image: it is already linux/amd64 with cryptography installed,
# so this build is a COPY rather than a cross-architecture pip install (which takes many minutes
# under emulation on an arm64 laptop). boto3 is pure-python and adds quickly.
FROM us-central1-docker.pkg.dev/pf-spiffe-demo-4412/demo/agent:rebuild
RUN pip install --no-cache-dir boto3
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8080
CMD ["python3", "app.py"]
