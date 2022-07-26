import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') #or 'ThisK3Y$houldB3S3cr3t'
uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri #or 'sqlite:///Webpollapp_Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


login_manager = LoginManager(app)
login_manager.login_view = 'login'


import routes