from flask import Blueprint, request
from app.db import query

bp = Blueprint("users", __name__)

@bp.route("/users", methods=["GET"])
def list_users():
    sort = request.args.get("sort", "id")
    # SQLi: user-controlled `sort` interpolated into raw SQL.
    return query(f"SELECT id, name FROM users ORDER BY {sort}")

@bp.route("/users", methods=["POST"])
def create_user():
    return {"ok": True}
