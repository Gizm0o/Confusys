# Confusys API

A Flask-based API for managing users, roles, and machines with secure JWT authentication and role-based access control.

## Features
- User registration and login with JWT authentication
- Role-based access control (users and machines can have multiple roles)
- Admin-only role management (create, update, delete, assign/remove roles)
- Machine management (CRUD, attach roles, secure by role)
- Default admin account created at startup
- Comprehensive test suite (pytest)

## Setup

1. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   - Create a `.env` file (optional) with:
     ```
     DATABASE_URL=sqlite:///confusys.db  # or your preferred DB URL
     SECRET_KEY=your-secret-key
     ```
   - Defaults: `SECRET_KEY=dev`, SQLite in-memory for tests.

3. **Run the app:**
   ```sh
   python app.py
   ```
   Or with Docker Compose:
   ```sh
   docker-compose up --build
   ```

4. **Default admin account:**
   - Username: `admin`
   - Password: `admin`
   - Email: `admin@example.com`

## API Overview

### Authentication
- Register: `POST /user/register`
- Login: `POST /user/login` (returns JWT token)
- Use the token in the `Authorization: Bearer <token>` header for all protected endpoints.

### Users
- Register: `POST /user/register` `{username, email, password}`
- Login: `POST /user/login` `{username, password}`

### Roles (admin only)
- Create: `POST /roles` `{name, description}`
- List: `GET /roles`
- Get: `GET /roles/<role_id>`
- Update: `PUT /roles/<role_id>` `{name, description}`
- Delete: `DELETE /roles/<role_id>`
- Assign to user: `POST /roles/<role_id>/assign_user/<user_id>`
- Remove from user: `POST /roles/<role_id>/remove_user/<user_id>`
- Assign to machine: `POST /roles/<role_id>/assign_machine/<machine_id>`
- Remove from machine: `POST /roles/<role_id>/remove_machine/<machine_id>`

### Machines
- Create: `POST /machines` `{name, description, roles: [role_name, ...]}`
- List: `GET /machines`
- Get: `GET /machines/<machine_id>`
- Update: `PUT /machines/<machine_id>` `{name, description, roles}`
- Delete: `DELETE /machines/<machine_id>`
- **Upload file to machine:** `POST /machines/<machine_id>/files` (multipart/form-data, field: `file`)
- **List files for machine:** `GET /machines/<machine_id>/files`
- **Delete file from machine:** `DELETE /machines/<machine_id>/files/<file_id>`

#### Example: Upload a file to a machine
```sh
curl -X POST http://localhost:5000/machines/<machine_id>/files \
  -H "Authorization: Bearer <user_token>" \
  -F "file=@/path/to/yourfile.txt"
```

#### Example: List files for a machine
```sh
curl -X GET http://localhost:5000/machines/<machine_id>/files \
  -H "Authorization: Bearer <user_token>"
```

#### Example: Delete a file from a machine
```sh
curl -X DELETE http://localhost:5000/machines/<machine_id>/files/<file_id> \
  -H "Authorization: Bearer <user_token>"
```
- Only users with a matching role (or admin) can upload, list, or delete files for a machine.

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