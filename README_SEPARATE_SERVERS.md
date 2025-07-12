# Confusys - Separate API and Frontend Servers

This setup runs the API and frontend on separate ports for better architecture and easier development.

## Architecture

- **API Server**: Runs on port 5000, serves only API endpoints
- **Frontend Server**: Runs on port 3000, serves the web UI and communicates with API

## Quick Start

### Option 1: Use the startup script (Recommended)
```bash
python start_servers.py
```

This will start both servers automatically.

### Option 2: Start servers separately

**Terminal 1 - API Server:**
```bash
python api_server.py
```

**Terminal 2 - Frontend Server:**
```bash
python frontend.py
```

## Access URLs

- **Frontend (Web UI)**: http://localhost:3000
- **API Server**: http://localhost:5000
- **Swagger Documentation**: http://localhost:5000/swagger

## Default Login

- **Username**: `admin`
- **Password**: `admin`

## Features

### Rules Management UI
- Upload YAML rule files
- Type rules directly with real-time validation
- View, download, and delete existing rules
- Role-based access control

### API Endpoints
- User authentication and management
- Machine management
- Role management
- Rule file management

## Development

### API Server (`api_server.py`)
- Serves only API endpoints
- No UI routes
- Database operations
- JWT authentication

### Frontend Server (`frontend.py`)
- Serves web UI
- Communicates with API via HTTP requests
- Session management
- Form handling and validation

## Benefits of Separate Servers

1. **Clean Architecture**: Clear separation between API and UI
2. **Easier Development**: Can modify frontend without restarting API
3. **Better Testing**: Can test API independently
4. **Scalability**: Can deploy API and frontend separately
5. **No Circular Dependencies**: Frontend makes HTTP calls to API

## Troubleshooting

### Port Already in Use
If you get "port already in use" errors:
- Kill existing processes: `netstat -ano | findstr :5000` (Windows) or `lsof -i :5000` (Linux/Mac)
- Or change ports in the respective files

### Database Issues
- Delete `confusys.db` to reset the database
- The API server will recreate it on startup

### CORS Issues
If you encounter CORS issues, the frontend is configured to handle them automatically. 