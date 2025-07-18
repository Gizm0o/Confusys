# Confusys - Local Development

This guide will help you run Confusys locally for development.

## Quick Start

### Option 1: Run Both Servers (Recommended)

Use the provided script to run both API and frontend servers:

```bash
python run_local.py
```

This will start:
- API Server: http://localhost:5000
- Frontend: http://localhost:3000
- Swagger UI: http://localhost:5000/swagger

### Option 2: Run Servers Separately

**Terminal 1 - API Server:**
```bash
python api_server.py
```

**Terminal 2 - Frontend Server:**
```bash
python frontend.py
```

### Option 3: Docker (Production-like)

```bash
docker-compose up
```

## Default Login

After starting the servers, you can log in with the default admin account:

- **Username:** admin
- **Password:** admin

## Troubleshooting

### Connection Refused Errors
- Make sure both servers are running
- Check that ports 5000 and 3000 are available
- Verify the API server is running before starting the frontend

### CSS Not Loading
- The static files should be served automatically
- Check that the `static/` folder exists with CSS files

### Authentication Issues
- The default admin user is created automatically
- If login fails, restart the API server to recreate the database

## Database File

- The SQLite database file `confusys.db` is generated automatically in the `instance/` directory for local development.
- This file should not be versioned or committed to the repository. It is ignored in Docker and can be safely deleted to reset the database state.
- To reset your database, simply delete `instance/confusys.db` and restart the application.

## Development Notes

- API server runs on port 5000
- Frontend server runs on port 3000
- Static files are served from the `static/` folder
- Templates are in the `templates/` folder
- Database is SQLite for local development, PostgreSQL for Docker 