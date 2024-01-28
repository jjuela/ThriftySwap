from flask import Flask, render_template,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager,login_user,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'csc400'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)  

class SwapShopUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Ensure that the app context is pushed
with app.app_context():
    db.create_all()
    print("Tables created successfully")

#FORMS
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if not existing_user_username:
            raise ValidationError("Username does not exist")

# THRIFTY OWL
@app.route('/home')
def home():
    return render_template('home.html')


@app.route ('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                print("User logged in!")
                return redirect(url_for('dashboard'))  
             
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        print("Form validated successfully!")
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        print("User added to the database!")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

#SWAP SHOP

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = SwapShopUser.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

    def validate_username(self, username):
        existing_user_username = SwapShopUser.query.filter_by(
            username=username.data).first()
        if not existing_user_username:
            raise ValidationError("Username does not exist")


@app.route('/swaplogin', methods=['GET', 'POST'])
def swaplogin():
    form = LoginForm()
    if form.validate_on_submit():
        user = SwapShopUser.query.filter_by(
            username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            print("User logged in!")
            return redirect(url_for('swapdashboard'))  # Update this line to use 'swapdashboard'
            
    return render_template('swaplogin.html', form=form)

@app.route('/swapdashboard', methods=['GET', 'POST'])
@login_required
def swapdashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def swaplogout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/swapregister', methods=['GET', 'POST'])
def swapregister():
    form = RegisterForm()

    if form.validate_on_submit():
        print("Form validated successfully!")
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = SwapShopUser(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        print("User added to the database!")
        return redirect(url_for('swaplogin'))

    return render_template('swap_register.html', form=form)





if __name__ == '__main__':
    app.run(debug=True)