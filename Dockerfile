FROM python:3.12-slim
RUN apt-get update -q && apt-get install -y ripgrep && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.py .
CMD ["python", "server.py"]
