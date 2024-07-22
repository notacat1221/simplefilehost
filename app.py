from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm

from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

import os
app = Flask(__name__)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
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

#Construct user class for database and create the associated db tables
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(120), unique = True, nullable = False)
    hashedPass = db.Column(db.string(120), nullable = False)
with app.app_context():
    db.create_all()


@app.route('/')
def hello_world():  # put application's code here
    return 'Sup dude!'

class LoginForm(FlaskForm):
    email = EmailField('Email', validators = [DataRequired(), Email()])
    password = PasswordField('Password', validators = [DataRequired()])
    submit = SubmitField('Login')
@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']


    return render_template('login.html')


if __name__ == '__main__':
    app.run()
