# Layer on the deployed AgentCore image: already ARM64 with boto3 + cryptography.
FROM 971422710168.dkr.ecr.ap-southeast-2.amazonaws.com/agentcore-agent:latest
COPY agent_b.py /app/agent_b.py
WORKDIR /app
EXPOSE 8080
CMD ["python3", "agent_b.py"]
