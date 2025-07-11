from flask import render_template

from api import create_app

app = create_app()


# Add Swagger documentation endpoint
@app.route("/docs")
def swagger_docs():
    """Return OpenAPI specification for the API"""
    swagger_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Confusys API",
            "version": "1.0.0",
            "description": "A Flask-based API for user, machine, and role management with audit script generation",
        },
        "servers": [
            {"url": "http://localhost:5000", "description": "Development server"}
        ],
        "paths": {
            "/user/register": {
                "post": {
                    "summary": "Register a new user",
                    "tags": ["Users"],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "email": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                    "required": ["username", "email", "password"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "User registered successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"message": {"type": "string"}},
                                    }
                                }
                            },
                        },
                        "400": {"description": "Missing required fields"},
                        "409": {"description": "User already exists"},
                    },
                }
            },
            "/user/login": {
                "post": {
                    "summary": "Login user",
                    "tags": ["Users"],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                    "required": ["username", "password"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Login successful",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {"type": "string"},
                                            "user_id": {"type": "string"},
                                            "token": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        },
                        "400": {"description": "Missing credentials"},
                        "401": {"description": "Invalid credentials"},
                    },
                }
            },
            "/machines": {
                "get": {
                    "summary": "List all machines",
                    "tags": ["Machines"],
                    "security": [{"Bearer": []}],
                    "responses": {
                        "200": {
                            "description": "List of machines",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "string"},
                                                "name": {"type": "string"},
                                                "ip_address": {"type": "string"},
                                                "technologies": {
                                                    "type": "array",
                                                    "items": {"type": "string"},
                                                },
                                            },
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "summary": "Register a new machine",
                    "tags": ["Machines"],
                    "security": [{"Bearer": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "ip_address": {"type": "string"},
                                        "technologies": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                    },
                                    "required": ["name", "ip_address"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Machine registered successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {"type": "string"},
                                            "machine_id": {"type": "string"},
                                            "script": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
            },
            "/machines/{machine_id}/script": {
                "get": {
                    "summary": "Download audit script for a machine",
                    "tags": ["Machines"],
                    "security": [{"Bearer": []}],
                    "parameters": [
                        {
                            "name": "machine_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Audit script file",
                            "content": {
                                "application/octet-stream": {
                                    "schema": {"type": "string", "format": "binary"}
                                }
                            },
                        },
                        "404": {"description": "Machine not found"},
                    },
                }
            },
            "/machines/{machine_id}/upload": {
                "post": {
                    "summary": "Upload a file as a machine and trigger automatic analysis",
                    "tags": ["Machines"],
                    "description": "Machines can upload files directly using their machine token. The file is automatically analyzed and a scan report is returned. Supports multi-language findings via the 'language' query parameter (e.g., ?language=en).",
                    "parameters": [
                        {
                            "name": "machine_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "language",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "example": "en"},
                            "description": "Language code for localized findings (e.g., 'en', 'fr').",
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"}
                                    },
                                    "required": ["file"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "File uploaded and analyzed successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "filename": {"type": "string"},
                                            "scan_results": {
                                                "type": "object",
                                                "properties": {
                                                    "total_findings": {
                                                        "type": "integer"
                                                    },
                                                    "critical_findings": {
                                                        "type": "integer"
                                                    },
                                                    "high_findings": {
                                                        "type": "integer"
                                                    },
                                                    "medium_findings": {
                                                        "type": "integer"
                                                    },
                                                    "findings": {
                                                        "type": "array",
                                                        "items": {
                                                            "type": "object",
                                                            "properties": {
                                                                "id": {
                                                                    "type": "string"
                                                                },
                                                                "description": {
                                                                    "type": "string"
                                                                },
                                                                "severity": {
                                                                    "type": "string"
                                                                },
                                                                "recommendation": {
                                                                    "type": "string"
                                                                },
                                                                "category": {
                                                                    "type": "string"
                                                                },
                                                                "match": {
                                                                    "type": "string"
                                                                },
                                                                "language": {
                                                                    "type": "string"
                                                                },
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    }
                                }
                            },
                        },
                        "401": {
                            "description": "Invalid machine token or machine not found"
                        },
                        "400": {"description": "No file part or invalid file"},
                    },
                    "security": [{"Bearer": []}],
                }
            },
            "/technologies": {
                "get": {
                    "summary": "List available technologies for audit scripts",
                    "tags": ["Machines"],
                    "responses": {
                        "200": {
                            "description": "List of available technologies",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/rules": {
                "get": {
                    "summary": "List all rule files",
                    "tags": ["Rules"],
                    "security": [{"Bearer": []}],
                    "responses": {
                        "200": {
                            "description": "List of rule files",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "string"},
                                                "filename": {"type": "string"},
                                                "upload_date": {"type": "string"},
                                            },
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "summary": "Upload a rule file",
                    "tags": ["Rules"],
                    "security": [{"Bearer": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"}
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Rule file uploaded successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {"type": "string"},
                                            "rule_id": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
            },
        },
        "components": {
            "securitySchemes": {
                "Bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            }
        },
    }
    return swagger_spec


@app.route("/swagger")
def swagger_ui():
    """Serve Swagger UI"""
    return render_template("swagger.html")


@app.route("/")
def index():
    return {"message": "Confusys API is running. Visit /swagger for API documentation."}


if __name__ == "__main__":
    app.run(debug=True)
