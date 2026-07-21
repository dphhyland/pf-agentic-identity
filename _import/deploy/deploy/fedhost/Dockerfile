# fedhost — static OpenID Federation entity host (stdlib Python, no deps).
# Both environments' content ship in the image; FEDHOST_CONTENT (config-as-code) picks the right one.
FROM python:3.12-slim
WORKDIR /app
COPY server.py content.staging.json content.production.json ./
EXPOSE 8080
CMD ["python", "server.py"]
