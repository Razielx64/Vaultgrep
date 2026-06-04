FROM python:3.12-slim

RUN apt-get update -q && \
    apt-get install -y --no-install-recommends ripgrep && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py .
COPY frontend/ frontend/

EXPOSE 8081
CMD ["python", "server.py"]
