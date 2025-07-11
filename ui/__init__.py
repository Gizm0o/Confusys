from flask import Blueprint

ui_bp = Blueprint("ui", __name__, template_folder="templates")

from ui import routes
