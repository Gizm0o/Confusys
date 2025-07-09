# Confusys API

A Flask-based API for user management and file parsing, using PostgreSQL for storage and Docker for deployment.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set up a PostgreSQL database and configure environment variables (see `.env.example`).
3. Run the Flask app:
   ```bash
   flask run
   ```
4. To run with Docker, see the Docker section below.

## Docker

Build and run the container:
```bash
docker build -t confusys-api .
docker run --env-file .env -p 5000:5000 confusys-api
```