# ui/routes.py
import requests
from flask import (
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import ui_bp


@ui_bp.route("/")
def home():
    return redirect(url_for("ui.login"))


@ui_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not username or not email or not password:
            flash("Tous les champs sont requis.", "danger")
            return redirect(url_for("ui.register"))

        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("ui.register"))

        response = requests.post(
            f"{current_app.config.get('API_URL', 'http://localhost:5000')}/user/register",
            json={"username": username, "email": email, "password": password},
        )

        if response.status_code == 201:
            flash("Inscription réussie. Connectez-vous !", "success")
            return redirect(url_for("ui.login"))
        else:
            flash("Erreur lors de l'inscription.", "danger")
            return redirect(url_for("ui.register"))

    return render_template("register.html")


@ui_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Champs requis", "danger")
            return redirect(url_for("ui.login"))

        # Request to the API for login
        response = requests.post(
            f"{current_app.config.get('API_URL', 'http://localhost:5000')}/user/login",
            json={"username": username, "password": password},
        )
        if response.status_code == 200:
            data = response.json()
            session["token"] = data["token"]
            session["username"] = username
            return redirect(url_for("ui.dashboard"))
        else:
            flash("Identifiants invalides", "danger")
            return redirect(url_for("ui.login"))

    return render_template("login.html")


@ui_bp.route("/logout")
def logout():
    session.clear()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("ui.login"))


@ui_bp.route("/dashboard")
def dashboard():
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get("http://localhost:5000/machines", headers=headers)
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
                }
                for m in raw_machines
            ]
    except Exception as e:
        current_app.logger.error(f"Failed to fetch machines: {e}")
        machines = []

    return render_template("dashboard.html", machines=machines)


@ui_bp.route("/machines/add", methods=["GET", "POST"])
def add_machine():
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    headers = {"Authorization": f"Bearer {token}"}

    # Retrieve roles and technologies from the API
    try:
        roles_resp = requests.get("http://localhost:5000/roles", headers=headers)
        tech_resp = requests.get("http://localhost:5000/machines/technologies")
        roles = roles_resp.json() if roles_resp.ok else []
        technologies = tech_resp.json() if tech_resp.ok else []
    except Exception:
        flash("Erreur lors de la récupération des données.", "danger")
        return redirect(url_for("ui.dashboard"))

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        selected_roles = request.form.getlist("roles")
        selected_techs = request.form.getlist("technologies")

        if not name:
            flash("Le nom est requis.", "danger")
            return redirect(url_for("ui.add_machine"))

        data = {
            "name": name,
            "description": description,
            "roles": selected_roles,
            "technologies": selected_techs,
        }

        resp = requests.post(
            "http://localhost:5000/machines", json=data, headers=headers
        )
        if resp.status_code == 201:
            flash("Machine ajoutée avec succès.", "success")
            return redirect(url_for("ui.dashboard"))
        else:
            flash("Erreur lors de l'ajout de la machine.", "danger")

    return render_template(
        "add_machine.html",
        roles=roles,
        technologies=technologies,
    )


@ui_bp.route("/machines/delete/<machine_id>", methods=["POST"])
def delete_machine(machine_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(
            f"http://localhost:5000/machines/{machine_id}", headers=headers
        )
        if resp.status_code == 200:
            flash("Machine supprimée.", "success")
        else:
            flash("Échec de la suppression.", "danger")
    except Exception:
        flash("Erreur de connexion à l'API.", "danger")

    return redirect(url_for("ui.dashboard"))


@ui_bp.route("/profile")
def profile():
    if "token" not in session:
        return redirect(url_for("ui.login"))

    username = session.get("username", "Inconnu")
    return render_template("profile.html", username=username)


@ui_bp.route("/about")
def about():
    return render_template("about.html")


@ui_bp.route("/machines/<machine_id>/view")
def view_machine(machine_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    headers = {"Authorization": f"Bearer {token}"}
    details_url = f"http://localhost:5000/machines/{machine_id}"
    script_url = f"http://localhost:5000/machines/{machine_id}/script"

    try:
        info = requests.get(details_url, headers=headers).json()
        script = requests.get(script_url, headers=headers).json()["script"]
        info["script"] = script
        info["technologies"] = info.get("technologies", [])  # <-- Ajout sécurité
    except Exception:
        flash("Erreur lors du chargement des détails de la machine.", "danger")
        return redirect(url_for("ui.dashboard"))

    return render_template("machine_detail.html", machine=info)


@ui_bp.route("/machines/<machine_id>/script/download")
def download_script(machine_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    headers = {"Authorization": f"Bearer {token}"}
    backend_url = f"http://localhost:5000/machines/{machine_id}/script/download"

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
        return redirect(url_for("ui.view_machine", machine_id=machine_id))


@ui_bp.route("/rules")
def rules():
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    # Use internal API calls instead of HTTP requests
    try:
        from api.models.user import Role
        from api.models.machine import Rule
        from api import db

        # Get roles
        roles = Role.query.all()
        roles_data = [
            {"name": role.name, "description": role.description} for role in roles
        ]

        # Get rules based on user permissions
        from api.routes.rule_routes import is_admin, user_can_access_rule
        from api.models.user import User
        import jwt

        # Decode token to get user
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        current_user = db.session.get(User, data["user_id"])

        if is_admin(current_user):
            rules = Rule.query.all()
        else:
            user_role_ids = [role.id for role in current_user.roles]
            rules = Rule.query.join(Rule.roles).filter(Role.id.in_(user_role_ids)).all()
            # Also include rules owned by the user
            owned_rules = Rule.query.filter_by(user_id=current_user.id).all()
            rules = list({r.id: r for r in rules + owned_rules}.values())

        rules_data = [
            {
                "id": r.id,
                "filename": r.filename,
                "description": r.description,
                "roles": [role.name for role in r.roles],
                "owner": r.user_id,
            }
            for r in rules
        ]

    except Exception as e:
        current_app.logger.error(f"Error in rules page: {e}")
        flash("Erreur lors de la récupération des données.", "danger")
        return redirect(url_for("ui.dashboard"))

    return render_template("rules.html", roles=roles_data, rules=rules_data)


@ui_bp.route("/rules/upload", methods=["POST"])
def upload_rules():
    token = session.get("token")
    if not token:
        return {"success": False, "error": "Non autorisé"}, 401

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
            import yaml

            content = file.read()
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            return {"success": False, "error": f"Format YAML invalide: {str(e)}"}

        # Reset file pointer for upload
        file.seek(0)

        # Use internal API call
        from api.models.machine import Rule
        from api.models.user import Role, User
        from api import db
        import jwt
        from werkzeug.utils import secure_filename

        # Decode token to get user
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        current_user = db.session.get(User, data["user_id"])

        filename = secure_filename(str(file.filename))
        file_data = file.read()
        role_objects = Role.query.filter(Role.name.in_(roles)).all() if roles else []

        rule = Rule(
            filename=filename,
            data=file_data,
            description=description,
            user_id=current_user.id,
        )
        rule.roles = role_objects
        db.session.add(rule)
        db.session.commit()

        return {"success": True}

    except Exception as e:
        return {"success": False, "error": f"Erreur: {str(e)}"}


@ui_bp.route("/rules/validate", methods=["POST"])
def validate_rules():
    token = session.get("token")
    if not token:
        return {"valid": False, "errors": ["Non autorisé"]}, 401

    try:
        content = request.form.get("content", "")
        if not content.strip():
            return {"valid": False, "errors": ["Contenu vide"]}

        import yaml

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


@ui_bp.route("/rules/save", methods=["POST"])
def save_rules():
    token = session.get("token")
    if not token:
        return {"success": False, "error": "Non autorisé"}, 401

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
            import yaml

            yaml.safe_load(content)
        except yaml.YAMLError as e:
            return {"success": False, "error": f"Format YAML invalide: {str(e)}"}

        # Use internal API call
        from api.models.machine import Rule
        from api.models.user import Role, User
        from api import db
        import jwt

        # Decode token to get user
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        current_user = db.session.get(User, data["user_id"])

        filename = "custom_rules.yml"
        file_data = content.encode("utf-8")
        role_objects = Role.query.filter(Role.name.in_(roles)).all() if roles else []

        rule = Rule(
            filename=filename,
            data=file_data,
            description=description,
            user_id=current_user.id,
        )
        rule.roles = role_objects
        db.session.add(rule)
        db.session.commit()

        return {"success": True}

    except Exception as e:
        return {"success": False, "error": f"Erreur: {str(e)}"}


@ui_bp.route("/rules/download/<rule_id>")
def download_rule(rule_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    try:
        from api.models.machine import Rule
        from api.models.user import User
        from api import db
        import jwt
        from api.routes.rule_routes import user_can_access_rule

        # Decode token to get user
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        current_user = db.session.get(User, data["user_id"])

        rule = db.session.get(Rule, rule_id)
        if not rule or not user_can_access_rule(current_user, rule):
            flash("Règle non trouvée ou accès refusé", "danger")
            return redirect(url_for("ui.rules"))

        from flask import Response

        return Response(
            rule.data,
            mimetype="application/x-yaml",
            headers={"Content-Disposition": f"attachment; filename={rule.filename}"},
        )

    except Exception as e:
        current_app.logger.error(f"Error downloading rule: {e}")
        flash("Erreur lors du téléchargement", "danger")
        return redirect(url_for("ui.rules"))


@ui_bp.route("/rules/delete/<rule_id>", methods=["POST"])
def delete_rule(rule_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    try:
        from api.models.machine import Rule
        from api.models.user import User
        from api import db
        import jwt
        from api.routes.rule_routes import user_can_access_rule, is_admin

        # Decode token to get user
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        current_user = db.session.get(User, data["user_id"])

        rule = db.session.get(Rule, rule_id)
        if not rule or not user_can_access_rule(current_user, rule):
            flash("Règle non trouvée ou accès refusé", "danger")
            return redirect(url_for("ui.rules"))

        # Only owner or admin can delete
        if not (is_admin(current_user) or rule.user_id == current_user.id):
            flash(
                "Seul le propriétaire ou l'admin peut supprimer cette règle", "danger"
            )
            return redirect(url_for("ui.rules"))

        db.session.delete(rule)
        db.session.commit()
        flash("Règle supprimée avec succès", "success")

    except Exception as e:
        current_app.logger.error(f"Error deleting rule: {e}")
        flash("Erreur lors de la suppression", "danger")

    return redirect(url_for("ui.rules"))


@ui_bp.route("/rules/view")
def view_rules():
    """Display all rules in a list view"""
    token = session.get("token")
    if not token:
        return redirect(url_for("ui.login"))

    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get("http://localhost:5000/rules", headers=headers)
        if resp.status_code != 200:
            flash("Erreur lors de la récupération des règles", "danger")
            rules = []
        else:
            rules = resp.json()
    except Exception as e:
        current_app.logger.error(f"Failed to fetch rules: {e}")
        flash("Erreur de connexion à l'API", "danger")
        rules = []

    return render_template("view_rules.html", rules=rules)
