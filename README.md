# Confusys API

A Flask-based API for user, machine, and role management with audit script generation and role-based access control.

## Features

- **User Management**: Registration, login, and JWT authentication
- **Role-Based Access Control**: Admin and user roles with different permissions
- **Machine Management**: Register machines with custom audit script generation
- **Rule File Management**: Upload and manage rule files
- **Modular Audit Scripts**: Select technologies to include in audit scripts
- **Swagger Documentation**: Interactive API documentation

## Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application**:
   ```bash
   python app.py
   ```

3. **Access the API**:
   - API Base URL: `http://localhost:5000`
   - Swagger Documentation: `http://localhost:5000/swagger`
   - OpenAPI Spec: `http://localhost:5000/docs`

## Testing

The project includes a comprehensive test suite that runs automatically in the CI/CD pipeline.

### Running Tests Locally

**Option 1: Using the test runner script**
```bash
python run_tests.py
```

**Option 2: Using pytest directly**
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=api --cov-report=html

# Run specific test file
pytest tests/test_user_api.py -v
```

### Test Coverage

The test suite covers:
- User registration and authentication
- Machine management and script generation
- Role-based access control
- Rule file management
- API endpoint validation

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/tests.yml`) runs on **every branch** for both push and pull request events. This ensures all code is tested regardless of branch.

### Pipeline Stages
1. **Code Quality Assurance**
   - Black (code formatting)
   - isort (import sorting)
   - flake8 (linting)
2. **Security Scanning**
   - Bandit (Python security linting)
   - Safety (dependency vulnerability scanning)
   - Security reports as artifacts
3. **Test Coverage Tracking**
   - pytest with coverage reporting
   - Codecov integration
   - HTML coverage reports
   - PostgreSQL integration tests
   - **Test pipeline is split by stage:**
     - API and upload flow (`test_machine_api.py`)
     - Report generation and DB verification (`test_report_generation.py`)
4. **Dependency Management**
   - Weekly dependency checks
   - Automated PR creation for updates
   - Dependabot integration

### Branch Triggers
- **Push:** All branches (`branches: [ "**" ]`)
- **Pull Requests:** All branches (`branches: [ "**" ]`)
- **Scheduled:** Weekly dependency checks

---

## Machine File Upload & Automatic Analysis

Machines can upload files directly and trigger automatic security analysis.

### Endpoint
`POST /machines/<machine_id>/upload`

**Headers:**
- `Authorization: Bearer <machine_token>`

**Form Data:**
- `file`: The file to upload

**Response Example:**
```json
{
  "id": "file_id",
  "filename": "audit_results.tar.gz",
  "scan_results": {
    "total_findings": 5,
    "critical_findings": 2,
    "high_findings": 1,
    "medium_findings": 2,
    "findings": [
      {
        "id": "SEC002",
        "description": "Container executed as root.",
        "severity": "High",
        "recommendation": "Use a non-root user in the Dockerfile.",
        "category": "Privileges",
        "match": "USER root"
      }
    ]
  }
}
```

---

## Multi-Language Rule Support

Rules can be written in multiple languages. The engine will use the system language or a `language` parameter (e.g., `?language=en`).

### Rule Example (YAML)
```yaml
- id: "SEC002"
  description: "Conteneur exécuté en tant que root."
  description_en: "Container executed as root."
  search: "USER root"
  severity: "High"
  category: "Privileges"
  category_en: "Privileges"
  recommendation: "Utilisez un utilisateur non root dans le Dockerfile."
  recommendation_en: "Use a non-root user in the Dockerfile."
```

### Usage
- The engine will use `description_en` if `language=en`, otherwise fallback to `description` (French by default in examples).
- Add more languages by adding fields like `description_es`, `recommendation_de`, etc.

---

## Rules File Structure

- Each technology has its own YAML file in the `rules/` directory.
- Each rule supports:
  - `id`, `description`, `description_en`, `search`, `regex`, `case_sensitive`, `severity`, `category`, `category_en`, `tags`, `recommendation`, `recommendation_en`, `example`, `example_en`, `reference`
- You can add as many languages as you want by suffixing the field with the language code.

---

## Test Structure

- **API and upload flow:** `tests/test_machine_api.py`
- **Report generation and DB verification:** `tests/test_report_generation.py`
- Run tests for each stage:
  ```bash
  pytest tests/test_machine_api.py
  pytest tests/test_report_generation.py
  ```

---

## Example: Machine Upload with Language

```bash
curl -X POST http://localhost:5000/machines/<machine_id>/upload \
  -H "Authorization: Bearer <machine_token>" \
  -F "file=@audit_results.tar.gz" \
  -G --data-urlencode "language=en"
```

---

## API Documentation

### Swagger UI

The API includes interactive Swagger documentation available at `/swagger`. This provides:

- **Interactive API Explorer**: Test endpoints directly from the browser
- **Request/Response Examples**: See expected request formats and responses
- **Authentication Support**: JWT Bearer token authentication
- **Endpoint Documentation**: Detailed descriptions of all API endpoints

To access the Swagger UI:
1. Start the application: `python app.py`
2. Open your browser to: `http://localhost:5000/swagger`
3. Use the interactive interface to explore and test the API

### API Endpoints

#### Authentication
- Register: `POST /user/register` `{username, email, password}`
- Login: `POST /user/login` `{username, password}`

#### Example: Register a user
```sh
curl -X POST http://localhost:5000/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure_password"
  }'
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### Example: Login
```sh
curl -X POST http://localhost:5000/user/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "secure_password"
  }'
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Roles (Admin Only)
- Create: `POST /roles` `{name, description}`
- List: `GET /roles`
- Delete: `DELETE /roles/<role_id>`
- Assign to user: `POST /roles/<role_id>/assign_user/<user_id>`
- Remove from user: `POST /roles/<role_id>/remove_user/<user_id>`
- Assign to machine: `POST /roles/<role_id>/assign_machine/<machine_id>`
- Remove from machine: `POST /roles/<role_id>/remove_machine/<machine_id>`

#### Example: Create a role
```sh
curl -X POST http://localhost:5000/roles \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "operator",
    "description": "System operator role"
  }'
```

**Response:**
```json
{
  "id": 2,
  "name": "operator",
  "description": "System operator role"
}
```

### Machines
- Create: `POST /machines` `{name, description, roles: [role_name, ...], technologies: [tech1, tech2, ...]}`
- List: `GET /machines`
- Get: `GET /machines/<machine_id>`
- Update: `PUT /machines/<machine_id>` `{name, description, roles}`
- Delete: `DELETE /machines/<machine_id>`
- **Upload file to machine:** `POST /machines/<machine_id>/files` (multipart/form-data, field: `file`)
- **List files for machine:** `GET /machines/<machine_id>/files`
- **Delete file from machine:** `DELETE /machines/<machine_id>/files/<file_id>`
- **Download audit script:** `GET /machines/<machine_id>/script`
- **List available technologies:** `GET /machines/technologies`

#### Example: Register a machine with custom technologies
```sh
curl -X POST http://localhost:5000/machines \
  -H "Authorization: Bearer <user_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "webserver01",
    "description": "Main web server",
    "roles": ["operator"],
    "technologies": ["os_kernel", "docker", "network", "users_auth"]
  }'
```

**Response:**
```json
{
  "machine_id": "550e8400-e29b-41d4-a716-446655440001",
  "token": "machine_registration_token_here",
  "script": "#!/bin/sh\n# Custom Linux Audit Script\n# Generated by Confusys\n\nTARGET_DIR=/tmp\nHOSTNAME=`hostname`\nAUDIT_NAME=\"AUDIT-$HOSTNAME-$(date +'%Y%m%d-%H%M%S')\"\nAUDIT_DIR=\"$TARGET_DIR/$AUDIT_NAME\"\nOUTFILE=\"$AUDIT_DIR.tar.gz\"\n\numask 077\nmkdir -p \"$AUDIT_DIR\"\ncd \"$AUDIT_DIR\"\n\n# OS and Kernel Info\nuname -a > uname.out 2>/dev/null\ncat /etc/*release* >> uname.out 2>/dev/null\nlsmod >lsmod.out 2>/dev/null\n/proc/config* > kernel-config.out 2>/dev/null\n\n# Docker Info\ndocker ps >docker.out 2>/dev/null\n\n# Network Info\nifconfig -a > ifconfig.out 2>/dev/null\nip a > ip.out 2>/dev/null\nnetstat -an > netstat-an.out 2>/dev/null\nss -an > ss-an.out 2>/dev/null\nnetstat -rn > netstat-rn.out 2>/dev/null\nip route show > ip-route.out 2>/dev/null\nnetstat -anp > netstat-anp.out 2>/dev/null\nss -anp > ss-anp.out 2>/dev/null\nss -lnp4 > ss.out\nss -lnp6 >> ss.out\n\n# Users and Authentication\ncat /etc/passwd > passwd.out 2>/dev/null\ncat /etc/shadow > shadow.out 2>/dev/null\ncat /etc/group > group.out 2>/dev/null\ncat /etc/sudoers > sudoers.out 2>/dev/null\ncat /etc/login* > login.out 2>/dev/null\ncat /etc/pam* > pam.out 2>/dev/null\n\ncd \"$TARGET_DIR\"\ntar czf \"$OUTFILE\" \"$AUDIT_NAME\"\necho \"$OUTFILE\" is finished, you may delete \"$AUDIT_DIR\" now.\nexit 0\n"
}
```

#### Example: List available technologies
```sh
curl -X GET http://localhost:5000/machines/technologies
```

**Response:**
```json
[
  {
    "key": "os_kernel",
    "description": "Operating system and kernel information"
  },
  {
    "key": "docker",
    "description": "Docker container information"
  },
  {
    "key": "network",
    "description": "Network interfaces and connections"
  },
  {
    "key": "users_auth",
    "description": "User accounts and authentication configuration"
  },
  {
    "key": "selinux",
    "description": "SELinux security status"
  }
]
```

#### Example: Download audit script
```sh
curl -X GET http://localhost:5000/machines/<machine_id>/script \
  -H "Authorization: Bearer <user_token>"
```

**Response:** Returns the bash script as a downloadable file.

#### Example: Upload a file to a machine
```sh
curl -X POST http://localhost:5000/machines/<machine_id>/files \
  -H "Authorization: Bearer <user_token>" \
  -F "file=@/path/to/yourfile.txt"
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "filename": "yourfile.txt"
}
```

#### Example: List files for a machine
```sh
curl -X GET http://localhost:5000/machines/<machine_id>/files \
  -H "Authorization: Bearer <user_token>"
```

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440002",
    "filename": "yourfile.txt"
  }
]
```

#### Example: Delete a file from a machine
```sh
curl -X DELETE http://localhost:5000/machines/<machine_id>/files/<file_id> \
  -H "Authorization: Bearer <user_token>"
```

**Response:**
```json
{
  "message": "File deleted successfully"
}
```

### Rules
- Upload: `POST /rules` (multipart/form-data, field: `file`, optional `description`, `roles`)
- List: `GET /rules`
- Get: `GET /rules/<rule_id>` (add `?download=1` to download the file)
- Update: `PUT /rules/<rule_id>` (multipart/form-data, owner or admin only)
- Delete: `DELETE /rules/<rule_id>` (owner or admin only)

Rules are files uploaded by users, associated with roles for access control. Only users with a matching role (or admin, or the owner) can manage or view a rule.

#### Example: Upload a rule file
```sh
curl -X POST http://localhost:5000/rules \
  -H "Authorization: Bearer <user_token>" \
  -F "file=@/path/to/yourrule.txt" \
  -F "description=My parsing rule" \
  -F "roles=operator" -F "roles=analyst"
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440003",
  "filename": "yourrule.txt",
  "description": "My parsing rule"
}
```

#### Example: List rules
```sh
curl -X GET http://localhost:5000/rules \
  -H "Authorization: Bearer <user_token>"
```

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440003",
    "filename": "yourrule.txt",
    "description": "My parsing rule",
    "roles": ["operator", "analyst"]
  }
]
```

#### Example: Get rule metadata
```sh
curl -X GET http://localhost:5000/rules/<rule_id> \
  -H "Authorization: Bearer <user_token>"
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440003",
  "filename": "yourrule.txt",
  "description": "My parsing rule",
  "roles": ["operator", "analyst"]
}
```

#### Example: Download a rule file
```sh
curl -X GET "http://localhost:5000/rules/<rule_id>?download=1" \
  -H "Authorization: Bearer <user_token>"
```

**Response:** Returns the rule file as a downloadable file.

## Example Usage

### Register and Login
```sh
curl -X POST http://localhost:5000/user/register \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "email": "user1@example.com", "password": "pass"}'

curl -X POST http://localhost:5000/user/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "pass"}'
# Response includes {"token": "..."}
```

### Create a Role (admin only)
```sh
curl -X POST http://localhost:5000/roles \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "operator", "description": "Operator role"}'
```

### Create a Machine (with role)
```sh
curl -X POST http://localhost:5000/machines \
  -H "Authorization: Bearer <user_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Machine1", "description": "Test machine", "roles": ["operator"]}'
```

## Testing
Run all tests with:
```sh
pytest tests/
```

## Notes
- Only admin users can manage roles and assign them to users/machines.
- Users can only access machines if they share at least one role with the machine, unless they are admin.
- All endpoints require JWT authentication except registration and login.