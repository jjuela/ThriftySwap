from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from config import Config
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    from models import User  # Import your User model here
    return User.query.get(user_id)

from routes import bp as routes_bp
app.register_blueprint(routes_bp)

if __name__ == '__main__':
    app.run(debug=True)
