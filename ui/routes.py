# ui/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import requests
from flask import current_app

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
