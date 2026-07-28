# Layer on the EKS workload image (linux/amd64, cryptography already present).
FROM 971422710168.dkr.ecr.ap-southeast-2.amazonaws.com/eks-workload:latest
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8080
CMD ["python3", "app.py"]
