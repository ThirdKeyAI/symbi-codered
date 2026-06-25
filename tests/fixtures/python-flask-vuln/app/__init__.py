from flask import Flask
from app.routes.users import bp as users_bp
from app.routes.admin import bp as admin_bp

app = Flask(__name__)
app.register_blueprint(users_bp)
app.register_blueprint(admin_bp)
