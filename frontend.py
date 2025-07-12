from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, Response
import requests
import yaml
from werkzeug.utils import secure_filename
import jwt
from io import BytesIO

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "frontend-secret-key"
app.config["API_URL"] = "http://localhost:5000"

# API URL configuration
import os
API_BASE_URL = os.environ.get("API_URL", "http://localhost:5000")

# Configure Flask app for static files
app.static_folder = "static"
app.static_url_path = "/static"

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not username or not email or not password:
            flash("Tous les champs sont requis.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("register"))

        response = requests.post(
            f"{API_BASE_URL}/user/register",
            json={"username": username, "email": email, "password": password},
        )

        if response.status_code == 201:
            flash("Inscription réussie. Connectez-vous !", "success")
            return redirect(url_for("login"))
        else:
            flash("Erreur lors de l'inscription.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

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
def dashboard():
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))

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
                }
                for m in raw_machines
            ]
    except Exception as e:
        app.logger.error(f"Failed to fetch machines: {e}")
        machines = []

    return render_template("dashboard.html", machines=machines)

@app.route("/machines/add", methods=["GET", "POST"])
def add_machine():
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))

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
def delete_machine(machine_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))

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
def profile():
    if "token" not in session:
        return redirect(url_for("login"))

    username = session.get("username", "Inconnu")
    return render_template("profile.html", username=username)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/rules")
def rules():
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))

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

@app.route("/rules/upload", methods=["POST"])
def upload_rules():
    token = session.get("token")
    if not token:
        return {"success": False, "error": "Non autorisé"}, 401

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
        
        resp = requests.post(f"{API_BASE_URL}/rules", headers=headers, files=files, data=data)
        
        if resp.status_code == 201:
            return {"success": True}
        else:
            error_data = resp.json() if resp.content else {}
            return {"success": False, "error": error_data.get("error", "Erreur lors de l'upload")}
            
    except Exception as e:
        return {"success": False, "error": f"Erreur: {str(e)}"}

@app.route("/rules/validate", methods=["POST"])
def validate_rules():
    token = session.get("token")
    if not token:
        return {"valid": False, "errors": ["Non autorisé"]}, 401
    
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
                required_fields = ["id", "description", "search", "severity", "category"]
                for field in required_fields:
                    if field not in rule:
                        errors.append(f"Règle {i+1}: champ '{field}' requis")
                
                # Validate severity
                if "severity" in rule:
                    valid_severities = ["Critical", "High", "Medium", "Low"]
                    if rule["severity"] not in valid_severities:
                        errors.append(f"Règle {i+1}: sévérité invalide. Valeurs autorisées: {', '.join(valid_severities)}")
                
                # Validate boolean fields
                boolean_fields = ["regex", "case_sensitive"]
                for field in boolean_fields:
                    if field in rule and not isinstance(rule[field], bool):
                        errors.append(f"Règle {i+1}: '{field}' doit être un booléen")
        
        return {"valid": len(errors) == 0, "errors": errors}
        
    except Exception as e:
        return {"valid": False, "errors": [f"Erreur de validation: {str(e)}"]}

@app.route("/rules/save", methods=["POST"])
def save_rules():
    token = session.get("token")
    if not token:
        return {"success": False, "error": "Non autorisé"}, 401

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
        file_data = BytesIO(content.encode('utf-8'))
        
        # Prepare form data for API
        files = {"file": ("custom_rules.yml", file_data, "application/x-yaml")}
        data = {"description": description}
        if roles:
            data["roles"] = roles
        
        resp = requests.post(f"{API_BASE_URL}/rules", headers=headers, files=files, data=data)
        
        if resp.status_code == 201:
            return {"success": True}
        else:
            error_data = resp.json() if resp.content else {}
            return {"success": False, "error": error_data.get("error", "Erreur lors de la sauvegarde")}
            
    except Exception as e:
        return {"success": False, "error": f"Erreur: {str(e)}"}

@app.route("/rules/download/<rule_id>")
def download_rule(rule_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))

    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.get(f"{API_BASE_URL}/rules/{rule_id}?download=1", headers=headers)
        
        if resp.status_code == 200:
            return Response(
                resp.content,
                mimetype="application/x-yaml",
                headers={"Content-Disposition": f"attachment; filename=rule_{rule_id}.yml"}
            )
        else:
            flash("Erreur lors du téléchargement", "danger")
            return redirect(url_for("rules"))
            
    except Exception:
        flash("Erreur de connexion", "danger")
        return redirect(url_for("rules"))

@app.route("/rules/delete/<rule_id>", methods=["POST"])
def delete_rule(rule_id):
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))

    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        resp = requests.delete(f"{API_BASE_URL}/rules/{rule_id}", headers=headers)
        
        if resp.status_code == 200:
            flash("Règle supprimée avec succès", "success")
        else:
            flash("Erreur lors de la suppression", "danger")
            
    except Exception:
        flash("Erreur de connexion", "danger")
    
    return redirect(url_for("rules"))

if __name__ == "__main__":
    app.run(debug=True, port=3000, host="0.0.0.0") 