FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends gcc && pip install -r requirements.txt && apt-get remove -y gcc && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY server.py .
EXPOSE 8761
CMD ["python", "-u", "server.py"]
