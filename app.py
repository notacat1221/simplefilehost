from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm

from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

import os
app = Flask(__name__)
bcrypt = Bcrypt(app)
BASE_DIR = 'share'

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_secret_key')
    #Securing session cookies
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    #Enable cross site request forgery protection using flask-wtf module
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY', 'default_csrf_secret_key')

    #Database config
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db' # Replace with prod DB
    #Debug flag
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True #Enable debugging flag
    SESSION_COOKIE_SECURE = False  # For local development
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db' #Use test DB

#Select config class
app.config.from_object(DevelopmentConfig)

#Validate security critical configs
SECRET_KEY = app.config.get('SECRET_KEY')
if not SECRET_KEY or SECRET_KEY == 'default_secret_key':
    raise ValueError('Please set a SECRET_KEY environment variable')

WTF_CSRF_SECRET_KEY = app.config.get('WTF_CSRF_SECRET_KEY')
if not WTF_CSRF_SECRET_KEY or WTF_CSRF_SECRET_KEY == 'default_csrf_secret_key':
    raise ValueError("No CSRF_SECRET_KEY set for Flask application. Please set it via environment variables.")

#Declare database now that SQL config is set
db = SQLAlchemy(app)

#Construct user class for database and create the associated db tables
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(120), unique = True, nullable = False)
    hashedPass = db.Column(db.String(120), nullable = False)
with app.app_context():
    db.create_all()

#Construct user validation and registration form classes
class LoginForm(FlaskForm):
    email = EmailField('Email', validators = [DataRequired(), Email()])
    password = PasswordField('Password', validators = [DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    email = EmailField('Email', validators = [DataRequired(), Email()])
    password = PasswordField('Password', validators = [DataRequired()])
    submit = SubmitField('Register')

#Ensure that user is properly authenticated with valid session data
@app.before_request
def require_login():
    if 'email' not in session and request.endpoint not in ['login', 'register']: # dont check authentication for login and register pages as unauthenticated users must still access
        return redirect(url_for('login'))

@app.route('/')
def landingZone():  # put application's code here
    if 'email' in session:
        return redirect(url_for('listFiles'))



@app.route('/login', methods = ['GET', 'POST'])
def login():
    if 'email' in session:
        return redirect(url_for('landingZone'))
    form = LoginForm()
    if form.validate_on_submit(): #Checks that submitted login form adheres to input validation rules
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.hashedPass, password): #Check stored password hash against input using bcrypt, ensure it matches to the correct user
            session['email'] = email #if user validated successfully, set email in session data so that user remains signed in
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html', form = form)

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        hashedPass = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, hashedPass=hashedPass)

        try:
            db.session.add(user)
            db.session.commit()
            flash('You have successfully registered! Now log in', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already registered', 'error')
    return render_template('register.html', form = form)

@app.route('/logout')
def logout():
    session.pop('email', None)
    return render_template('logout.html')

#Filepath routing
@app.route('/share', defaults={'subpath': ''})
@app.route('/share/<path:subpath>')
def listFiles(subpath):
    # Normalize the subpath to remove any trailing slashes
    subpath = subpath.rstrip('/')
    fullPath = os.path.join(BASE_DIR, subpath)

    if not os.path.exists(fullPath):
        flash('No such directory found')
        return redirect(url_for('listFiles'))
        print("no directory")

    parentPath = os.path.dirname(subpath)
    items = []

    try:
        with os.scandir(fullPath) as currentDir:
            for entry in currentDir:
                try:
                    items.append({
                        'name': entry.name,
                        'is_dir': entry.is_dir(),
                        'path': os.path.join(subpath, entry.name)
                    })
                except PermissionError:
                    flash(f'Permission denied on {entry.name}.', 'error')
    except PermissionError:
        flash('Permission denied for the directory.', 'error')

    return render_template('share.html', items=items, parentPath=parentPath, subpath=subpath)


if __name__ == '__main__':
    app.run()
