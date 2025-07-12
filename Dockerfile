# Use official Python image
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies including PostgreSQL development headers
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
EXPOSE 3000

# Entrypoint is set by docker-compose
CMD ["python", "api_server.py"] 