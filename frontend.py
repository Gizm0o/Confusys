import os
from io import BytesIO

import jwt
import requests
import yaml
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "frontend-secret-key"

# API URL configuration
API_BASE_URL = os.environ.get("API_URL", "http://api:5000")


# Helper functions for role checking
def is_admin():
    """Check if current user is admin"""
    return "admin" in session.get("user_roles", [])


def has_role(role_name):
    """Check if current user has a specific role"""
    return role_name in session.get("user_roles", [])


def login_required(f):
    """Decorator to require login for routes"""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("token"):
            flash("Veuillez vous connecter pour accéder à cette page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Make helper functions available to templates
app.jinja_env.globals.update(is_admin=is_admin, has_role=has_role)


@app.route("/")
def home():
    return redirect(url_for("login"))





@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Champs requis", "danger")
            return redirect(url_for("login"))

        response = requests.post(
            f"{API_BASE_URL}/user/login",
            json={"username": username, "password": password},
        )
        if response.status_code == 200:
            data = response.json()
            session["token"] = data["token"]
            session["username"] = username

            # Fetch user details including roles
            headers = {"Authorization": f"Bearer {data['token']}"}
            try:
                user_response = requests.get(
                    f"{API_BASE_URL}/user/users/{data['user_id']}", headers=headers
                )
                if user_response.status_code == 200:
                    user_data = user_response.json()
                    session["user_roles"] = user_data.get("roles", [])
                else:
                    session["user_roles"] = []
            except Exception:
                session["user_roles"] = []

            return redirect(url_for("dashboard"))
        else:
            flash("Identifiants invalides", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(f"{API_BASE_URL}/machines", headers=headers)
        if resp.status_code != 200:
            machines = []
        else:
            raw_machines = resp.json()
            machines = [
                {
                    "id": m["id"],
                    "name": m["name"],
                    "description": m.get("description", ""),
                    "roles": m.get("roles", []),
                    "technologies": m.get("technologies", []),
                    "has_findings": m.get("has_findings", False),
                    "total_findings": m.get("total_findings", 0),
                    "audit_score": m.get("audit_score", 100),
                }
                for m in raw_machines
            ]
            if machines:
                total_score = sum(m.get("audit_score", 100) for m in machines)
                global_score = round(total_score / len(machines))
            else:
                global_score = 100

    except Exception as e:
        app.logger.error(f"Failed to fetch machines: {e}")
        machines = []

    return render_template(
        "dashboard.html", machines=machines, global_score=global_score
    )


@app.route("/machines/add", methods=["GET", "POST"])
@login_required
def add_machine():
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    try:
        roles_resp = requests.get(f"{API_BASE_URL}/roles", headers=headers)
        tech_resp = requests.get(f"{API_BASE_URL}/machines/technologies")
        roles = roles_resp.json() if roles_resp.ok else []
        technologies = tech_resp.json() if tech_resp.ok else []
    except Exception:
        flash("Erreur lors de la récupération des données.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        selected_roles = request.form.getlist("roles")
        selected_techs = request.form.getlist("technologies")

        if not name:
            flash("Le nom est requis.", "danger")
            return redirect(url_for("add_machine"))

        data = {
            "name": name,
            "description": description,
            "roles": selected_roles,
            "technologies": selected_techs,
        }

        resp = requests.post(f"{API_BASE_URL}/machines", json=data, headers=headers)
        if resp.status_code == 201:
            flash("Machine ajoutée avec succès.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Erreur lors de l'ajout de la machine.", "danger")

    return render_template("add_machine.html", roles=roles, technologies=technologies)


@app.route("/machines/delete/<machine_id>", methods=["POST"])
@login_required
def delete_machine(machine_id):
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(f"{API_BASE_URL}/machines/{machine_id}", headers=headers)
        if resp.status_code == 200:
            flash("Machine supprimée.", "success")
        else:
            flash("Échec de la suppression.", "danger")
    except Exception:
        flash("Erreur de connexion à l'API.", "danger")

    return redirect(url_for("dashboard"))


@app.route("/profile")
@login_required
def profile():
    username = session.get("username", "Inconnu")
    return render_template("profile.html", username=username)


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/machines/<machine_id>/view")
@login_required
def view_machine(machine_id):
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    details_url = f"{API_BASE_URL}/machines/{machine_id}"
    script_url = f"{API_BASE_URL}/machines/{machine_id}/script"

    try:
        info_resp = requests.get(details_url, headers=headers)
        script_resp = requests.get(script_url, headers=headers)

        if info_resp.status_code != 200 or script_resp.status_code != 200:
            flash("Erreur lors du chargement de la machine ou du script.", "danger")
            return redirect(url_for("dashboard"))

        info = info_resp.json()
        script = script_resp.json().get("script", "")

        info["script"] = script
        info["roles"] = info.get("roles", [])
        info["technologies"] = info.get("technologies", [])
        info["scan_reports"] = info.get("scan_reports", [])

        # Add score based on findings
        for report in info.get("scan_reports", []):
            severities = [f.get("severity", "").lower() for f in report["findings"]]
            if "critical" in severities:
                report["score"] = "danger"
            elif "high" in severities:
                report["score"] = "warning"
            elif "medium" in severities:
                report["score"] = "info"
            else:
                report["score"] = "success"

    except Exception as e:
        app.logger.error(f"Erreur détail machine : {e}")
        flash("Erreur lors du chargement des détails.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("machine_detail.html", machine=info)


@app.route("/machines/<machine_id>/script/download")
@login_required
def download_script(machine_id):
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    backend_url = f"{API_BASE_URL}/machines/{machine_id}/script/download"

    response = requests.get(backend_url, headers=headers, stream=True)
    if response.status_code == 200:
        return Response(
            response.iter_content(chunk_size=1024),
            content_type=response.headers.get(
                "Content-Type", "application/octet-stream"
            ),
            headers={
                "Content-Disposition": response.headers.get(
                    "Content-Disposition", f'attachment; filename="audit_script.sh"'
                )
            },
        )
    else:
        flash("Erreur lors du téléchargement du script.", "danger")
        return redirect(url_for("view_machine", machine_id=machine_id))



@app.route("/rules")
@login_required
def rules():
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    try:
        roles_resp = requests.get(f"{API_BASE_URL}/roles", headers=headers)
        rules_resp = requests.get(f"{API_BASE_URL}/rules", headers=headers)
        roles = roles_resp.json() if roles_resp.ok else []
        rules = rules_resp.json() if rules_resp.ok else []
    except Exception:
        flash("Erreur lors de la récupération des données.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("rules.html", roles=roles, rules=rules)


@app.route("/rules/view")
@login_required
def view_rules():
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        rules_resp = requests.get(f"{API_BASE_URL}/rules", headers=headers)
        rules = rules_resp.json() if rules_resp.ok else []
    except Exception:
        flash("Erreur lors de la récupération des règles.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("view_rules.html", rules=rules)


@app.route("/rules/<rule_id>")
@login_required
def view_rule_detail(rule_id):
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        rule_resp = requests.get(f"{API_BASE_URL}/rules/{rule_id}", headers=headers)
        if rule_resp.status_code == 200:
            rule = rule_resp.json()
            # Parse created_at if it exists
            if rule.get("created_at"):
                from datetime import datetime

                try:
                    rule["created_at"] = datetime.fromisoformat(
                        rule["created_at"].replace("Z", "+00:00")
                    )
                except:
                    rule["created_at"] = None
            return render_template("rule_detail.html", rule=rule)
        else:
            flash("Règle non trouvée ou accès refusé.", "danger")
            return redirect(url_for("view_rules"))
    except Exception:
        flash("Erreur lors de la récupération de la règle.", "danger")
        return redirect(url_for("view_rules"))


@app.route("/rules/<rule_id>/edit", methods=["GET", "POST"])
@login_required
def edit_rule(rule_id):
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    if request.method == "GET":
        try:
            rule_resp = requests.get(f"{API_BASE_URL}/rules/{rule_id}", headers=headers)
            roles_resp = requests.get(f"{API_BASE_URL}/roles", headers=headers)

            if rule_resp.status_code == 200:
                rule = rule_resp.json()
                # Parse created_at if it exists
                if rule.get("created_at"):
                    from datetime import datetime

                    try:
                        rule["created_at"] = datetime.fromisoformat(
                            rule["created_at"].replace("Z", "+00:00")
                        )
                    except:
                        rule["created_at"] = None
                roles = roles_resp.json() if roles_resp.ok else []
                return render_template("edit_rule.html", rule=rule, roles=roles)
            else:
                flash("Règle non trouvée ou accès refusé.", "danger")
                return redirect(url_for("view_rules"))
        except Exception:
            flash("Erreur lors de la récupération de la règle.", "danger")
            return redirect(url_for("view_rules"))

    # POST - Update rule
    try:
        description = request.form.get("description")
        content = request.form.get("content")
        roles = request.form.getlist("roles")
        technologies = request.form.getlist("technologies")

        data = {"description": description}
        if content:
            data["content"] = content
        if roles:
            data["roles"] = roles
        if technologies:
            data["technologies"] = technologies

        resp = requests.put(
            f"{API_BASE_URL}/rules/{rule_id}", headers=headers, data=data
        )

        if resp.status_code == 200:
            flash("Règle mise à jour avec succès.", "success")
            return redirect(url_for("view_rule_detail", rule_id=rule_id))
        else:
            flash("Erreur lors de la mise à jour de la règle.", "danger")
            return redirect(url_for("edit_rule", rule_id=rule_id))

    except Exception:
        flash("Erreur de connexion.", "danger")
        return redirect(url_for("edit_rule", rule_id=rule_id))


@app.route("/rules/upload", methods=["POST"])
@login_required
def upload_rules():
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    try:
        file = request.files.get("file")
        description = request.form.get("description")
        roles = request.form.getlist("roles")

        if not file or not file.filename:
            return {"success": False, "error": "Aucun fichier sélectionné"}

        if not description:
            return {"success": False, "error": "Description requise"}

        # Validate YAML format
        try:
            content = file.read()
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            return {"success": False, "error": f"Format YAML invalide: {str(e)}"}

        # Reset file pointer for upload
        file.seek(0)

        # Prepare form data for API
        files = {"file": (file.filename, file, file.content_type)}
        data = {"description": description}
        if roles:
            data["roles"] = roles
        technologies = request.form.getlist("technologies")
        if technologies:
            data["technologies"] = technologies

        resp = requests.post(
            f"{API_BASE_URL}/rules", headers=headers, files=files, data=data
        )

        if resp.status_code == 201:
            return {"success": True}
        else:
            error_data = resp.json() if resp.content else {}
            return {
                "success": False,
                "error": error_data.get("error", "Erreur lors de l'upload"),
            }

    except Exception as e:
        return {"success": False, "error": f"Erreur: {str(e)}"}


@app.route("/rules/validate", methods=["POST"])
@login_required
def validate_rules():
    token = session.get("token")

    try:
        content = request.form.get("content", "")
        if not content.strip():
            return {"valid": False, "errors": ["Contenu vide"]}

        errors = []

        # Parse YAML
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            return {"valid": False, "errors": [f"Erreur de syntaxe YAML: {str(e)}"]}

        # Validate structure
        if not isinstance(data, dict):
            errors.append("Le contenu doit être un objet YAML")

        if "rules" not in data:
            errors.append("Le fichier doit contenir une section 'rules'")
        elif not isinstance(data["rules"], list):
            errors.append("La section 'rules' doit être une liste")
        else:
            # Validate each rule
            for i, rule in enumerate(data["rules"]):
                if not isinstance(rule, dict):
                    errors.append(f"Règle {i+1}: doit être un objet")
                    continue

                # Required fields
                required_fields = [
                    "id",
                    "description",
                    "search",
                    "severity",
                    "category",
                ]
                for field in required_fields:
                    if field not in rule:
                        errors.append(f"Règle {i+1}: champ '{field}' requis")

                # Validate severity
                if "severity" in rule:
                    valid_severities = ["Critical", "High", "Medium", "Low"]
                    if rule["severity"] not in valid_severities:
                        errors.append(
                            f"Règle {i+1}: sévérité invalide. Valeurs autorisées: {', '.join(valid_severities)}"
                        )

                # Validate boolean fields
                boolean_fields = ["regex", "case_sensitive"]
                for field in boolean_fields:
                    if field in rule and not isinstance(rule[field], bool):
                        errors.append(f"Règle {i+1}: '{field}' doit être un booléen")

        return {"valid": len(errors) == 0, "errors": errors}

    except Exception as e:
        return {"valid": False, "errors": [f"Erreur de validation: {str(e)}"]}


@app.route("/rules/save", methods=["POST"])
@login_required
def save_rules():
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    try:
        content = request.form.get("content", "")
        description = request.form.get("description")
        roles = request.form.getlist("roles")

        if not content.strip():
            return {"success": False, "error": "Contenu vide"}

        if not description:
            return {"success": False, "error": "Description requise"}

        # Validate YAML format
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            return {"success": False, "error": f"Format YAML invalide: {str(e)}"}

        # Create a temporary file for upload
        file_data = BytesIO(content.encode("utf-8"))

        # Prepare form data for API
        files = {"file": ("custom_rules.yml", file_data, "application/x-yaml")}
        data = {"description": description}
        if roles:
            data["roles"] = roles
        technologies = request.form.getlist("technologies")
        if technologies:
            data["technologies"] = technologies

        resp = requests.post(
            f"{API_BASE_URL}/rules", headers=headers, files=files, data=data
        )

        if resp.status_code == 201:
            return {"success": True}
        else:
            error_data = resp.json() if resp.content else {}
            return {
                "success": False,
                "error": error_data.get("error", "Erreur lors de la sauvegarde"),
            }

    except Exception as e:
        return {"success": False, "error": f"Erreur: {str(e)}"}


@app.route("/rules/download/<rule_id>")
@login_required
def download_rule(rule_id):
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    try:
        resp = requests.get(
            f"{API_BASE_URL}/rules/{rule_id}?download=1", headers=headers
        )

        if resp.status_code == 200:
            return Response(
                resp.content,
                mimetype="application/x-yaml",
                headers={
                    "Content-Disposition": f"attachment; filename=rule_{rule_id}.yml"
                },
            )
        else:
            flash("Erreur lors du téléchargement", "danger")
            return redirect(url_for("rules"))

    except Exception:
        flash("Erreur de connexion", "danger")
        return redirect(url_for("rules"))


@app.route("/rules/delete/<rule_id>", methods=["POST"])
@login_required
def delete_rule(rule_id):
    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(f"{API_BASE_URL}/rules/{rule_id}", headers=headers)
        if resp.status_code == 200:
            flash("Règle supprimée.", "success")
        else:
            flash("Échec de la suppression.", "danger")
    except Exception:
        flash("Erreur de connexion à l'API.", "danger")

    return redirect(url_for("view_rules"))


# User Management Routes (Admin Only)
@app.route("/admin/users")
@login_required
def admin_users():
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        users_resp = requests.get(f"{API_BASE_URL}/user/users", headers=headers)
        roles_resp = requests.get(f"{API_BASE_URL}/user/roles", headers=headers)

        if users_resp.status_code == 200 and roles_resp.status_code == 200:
            users = users_resp.json()
            roles = roles_resp.json()
            return render_template("admin_users.html", users=users, roles=roles)
        else:
            flash(
                "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
                "danger",
            )
            return redirect(url_for("dashboard"))
    except Exception:
        flash("Erreur lors de la récupération des données.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/admin/users/create", methods=["GET", "POST"])
@login_required
def create_user():
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    if request.method == "GET":
        try:
            roles_resp = requests.get(f"{API_BASE_URL}/user/roles", headers=headers)
            if roles_resp.status_code == 200:
                roles = roles_resp.json()
                return render_template("create_user.html", roles=roles)
            else:
                flash("Accès refusé.", "danger")
                return redirect(url_for("admin_users"))
        except Exception:
            flash("Erreur lors de la récupération des rôles.", "danger")
            return redirect(url_for("admin_users"))

    # POST - Create user
    try:
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        selected_roles = request.form.getlist("roles")

        if not username or not password:
            flash("Le nom d'utilisateur et le mot de passe sont requis.", "danger")
            return redirect(url_for("create_user"))

        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("create_user"))

        data = {"username": username, "password": password, "roles": selected_roles}

        # Only include email if it's provided
        if email:
            data["email"] = email

        resp = requests.post(f"{API_BASE_URL}/user/users", headers=headers, json=data)

        if resp.status_code == 201:
            flash("Utilisateur créé avec succès.", "success")
            return redirect(url_for("admin_users"))
        else:
            error_data = resp.json() if resp.content else {}
            flash(
                f"Erreur: {error_data.get('error', 'Erreur lors de la création')}",
                "danger",
            )
            return redirect(url_for("create_user"))

    except Exception:
        flash("Erreur de connexion.", "danger")
        return redirect(url_for("create_user"))


@app.route("/admin/users/<user_id>/edit", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    if request.method == "GET":
        try:
            user_resp = requests.get(
                f"{API_BASE_URL}/user/users/{user_id}", headers=headers
            )
            roles_resp = requests.get(f"{API_BASE_URL}/user/roles", headers=headers)

            if user_resp.status_code == 200 and roles_resp.status_code == 200:
                user = user_resp.json()
                roles = roles_resp.json()
                return render_template("edit_user.html", user=user, roles=roles)
            else:
                flash("Utilisateur non trouvé ou accès refusé.", "danger")
                return redirect(url_for("admin_users"))
        except Exception:
            flash("Erreur lors de la récupération de l'utilisateur.", "danger")
            return redirect(url_for("admin_users"))

    # POST - Update user
    try:
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        selected_roles = request.form.getlist("roles")

        data = {"username": username, "roles": selected_roles}

        # Only include email if it's provided
        if email:
            data["email"] = email

        if password:
            data["password"] = password

        resp = requests.put(
            f"{API_BASE_URL}/user/users/{user_id}", headers=headers, json=data
        )

        if resp.status_code == 200:
            flash("Utilisateur mis à jour avec succès.", "success")
            return redirect(url_for("admin_users"))
        else:
            error_data = resp.json() if resp.content else {}
            flash(
                f"Erreur: {error_data.get('error', 'Erreur lors de la mise à jour')}",
                "danger",
            )
            return redirect(url_for("edit_user", user_id=user_id))

    except Exception:
        flash("Erreur de connexion.", "danger")
        return redirect(url_for("edit_user", user_id=user_id))


@app.route("/admin/users/<user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(f"{API_BASE_URL}/user/users/{user_id}", headers=headers)
        if resp.status_code == 200:
            flash("Utilisateur supprimé.", "success")
        else:
            error_data = resp.json() if resp.content else {}
            flash(
                f"Erreur: {error_data.get('error', 'Échec de la suppression')}",
                "danger",
            )
    except Exception:
        flash("Erreur de connexion à l'API.", "danger")

    return redirect(url_for("admin_users"))


@app.route("/admin/roles")
@login_required
def admin_roles():
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        roles_resp = requests.get(f"{API_BASE_URL}/user/roles", headers=headers)

        if roles_resp.status_code == 200:
            roles = roles_resp.json()
            return render_template("admin_roles.html", roles=roles)
        else:
            flash(
                "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
                "danger",
            )
            return redirect(url_for("dashboard"))
    except Exception:
        flash("Erreur lors de la récupération des données.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/admin/roles/create", methods=["GET", "POST"])
@login_required
def create_role():
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    if request.method == "GET":
        return render_template("create_role.html")

    # POST - Create role
    try:
        name = request.form.get("name")
        description = request.form.get("description", "")

        if not name:
            flash("Le nom du rôle est requis.", "danger")
            return redirect(url_for("create_role"))

        data = {"name": name, "description": description}

        resp = requests.post(f"{API_BASE_URL}/user/roles", headers=headers, json=data)

        if resp.status_code == 201:
            flash("Rôle créé avec succès.", "success")
            return redirect(url_for("admin_roles"))
        else:
            error_data = resp.json() if resp.content else {}
            flash(
                f"Erreur: {error_data.get('error', 'Erreur lors de la création')}",
                "danger",
            )
            return redirect(url_for("create_role"))

    except Exception:
        flash("Erreur de connexion.", "danger")
        return redirect(url_for("create_role"))


@app.route("/admin/roles/<role_id>/edit", methods=["GET", "POST"])
@login_required
def edit_role(role_id):
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}

    if request.method == "GET":
        try:
            role_resp = requests.get(
                f"{API_BASE_URL}/user/roles/{role_id}", headers=headers
            )

            if role_resp.status_code == 200:
                role = role_resp.json()
                return render_template("edit_role.html", role=role)
            else:
                flash("Rôle non trouvé ou accès refusé.", "danger")
                return redirect(url_for("admin_roles"))
        except Exception:
            flash("Erreur lors de la récupération du rôle.", "danger")
            return redirect(url_for("admin_roles"))

    # POST - Update role
    try:
        name = request.form.get("name")
        description = request.form.get("description", "")

        data = {"name": name, "description": description}

        resp = requests.put(
            f"{API_BASE_URL}/user/roles/{role_id}", headers=headers, json=data
        )

        if resp.status_code == 200:
            flash("Rôle mis à jour avec succès.", "success")
            return redirect(url_for("admin_roles"))
        else:
            error_data = resp.json() if resp.content else {}
            flash(
                f"Erreur: {error_data.get('error', 'Erreur lors de la mise à jour')}",
                "danger",
            )
            return redirect(url_for("edit_role", role_id=role_id))

    except Exception:
        flash("Erreur de connexion.", "danger")
        return redirect(url_for("edit_role", role_id=role_id))


@app.route("/admin/roles/<role_id>/delete", methods=["POST"])
@login_required
def delete_role(role_id):
    # Check if user is admin
    if not is_admin():
        flash(
            "Accès refusé. Seuls les administrateurs peuvent accéder à cette page.",
            "danger",
        )
        return redirect(url_for("dashboard"))

    token = session.get("token")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(f"{API_BASE_URL}/user/roles/{role_id}", headers=headers)
        if resp.status_code == 200:
            flash("Rôle supprimé.", "success")
        else:
            error_data = resp.json() if resp.content else {}
            flash(
                f"Erreur: {error_data.get('error', 'Échec de la suppression')}",
                "danger",
            )
    except Exception:
        flash("Erreur de connexion à l'API.", "danger")

    return redirect(url_for("admin_roles"))


if __name__ == "__main__":
    app.run(debug=True, port=3000, host="0.0.0.0")
