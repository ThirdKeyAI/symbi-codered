from flask import Blueprint

bp = Blueprint("admin", __name__, url_prefix="/admin")

@bp.route("/dashboard", methods=["GET"])
def dashboard():
    return {"ok": True}

@bp.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    return {"deleted": user_id}
