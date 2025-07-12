#!/usr/bin/env python3
"""
Local development script for Confusys
Runs both API and Frontend servers for local development
"""

import subprocess
import sys
import time
import os
from threading import Thread


def start_api_server():
    """Start the API server on port 5000"""
    print("Starting API server on port 5000...")
    subprocess.run([sys.executable, "api_server.py"])


def start_frontend_server():
    """Start the frontend server on port 3000"""
    print("Starting Frontend server on port 3000...")
    subprocess.run([sys.executable, "frontend.py"])


def main():
    print("Confusys - Local Development")
    print("=" * 40)
    print("API Server: http://localhost:5000")
    print("Frontend: http://localhost:3000")
    print("Swagger UI: http://localhost:5000/swagger")
    print("\nPress Ctrl+C to stop all servers")
    print("=" * 40)

    # Start API server in a separate thread
    api_thread = Thread(target=start_api_server, daemon=True)
    api_thread.start()

    # Wait a moment for API to start
    time.sleep(3)

    # Start frontend server in main thread
    start_frontend_server()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        sys.exit(0)
