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
        info["technologies"] = info.get("technologies", [])
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
