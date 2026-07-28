# Layer on the existing GKE demo agent image: it is already linux/amd64 with cryptography installed,
# so this build is a COPY rather than a cross-architecture pip install (which takes many minutes
# under emulation on an arm64 laptop). boto3 is pure-python and adds quickly.
FROM us-central1-docker.pkg.dev/pf-spiffe-demo-7264/demo/agent@sha256:3979b01acf26a4a4ef26e82a227b44032ee190d74154c28ede6fa6c9e41d8e3e
RUN pip install --no-cache-dir boto3
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8080
CMD ["python3", "app.py"]
