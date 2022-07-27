from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask import request
import json
import string
import random

from main import db, login_manager

# Short url generating function used in creating new polls
def url_generator(size=12, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

# Function to get user ip - used in IP verification check
def get_ip():
    return request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

# Function to add new IP_check object to database when voting
def add_ip(poll_id, option_id):
    ip = get_ip()
    new_ip = IP_check(ip=ip, poll_id=poll_id, option_id=option_id)
    db.session.add(new_ip)
    db.session.commit

#  Declaration of user model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    joined_at = db.Column(db.DateTime(), default=datetime.utcnow, index=True)


    def __repr__(self):
        return f'<User id: {self.id}, Username: {self.username}, email: {self.email}, Joined: {self.joined_at}>'

    # Function to hash password before putting in database
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Function to compare password from input password with hashed password from database
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# User loader
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

#  Declaration of Poll model
class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True) # ID
    title = db.Column(db.String(128), index=True, unique=False) # Title of poll
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Foreign key to User.id
    options = db.relationship('Poll_option', backref='poll', lazy='dynamic', cascade='all, delete, delete-orphan') # relationship (one to many) to Poll_option models
    url = db.Column(db.String(16), index=True, unique=True) # Short url field
    private = db.Column(db.Boolean, index=True, unique=False) # Poll privacy option - non private polls are visible on main page, private ones can be only accessed by link
    is_active = db.Column(db.Boolean, index=True, unique=False) # Poll active option - non active polls cannot be voted
    verification = db.Column(db.String(16), index=True, unique=False) # Poll for way of vote verification either ('Cookie check'/'IP check'/'None')

#  Declaration of Poll_option models with with Foreign key to Poll.id or User.id
class Poll_option(db.Model):
    id = db.Column(db.Integer, primary_key=True) # ID
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id')) # Foreign key to Poll.id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Foreign key to User.id
    answer = db.Column(db.String(64), index=True, unique=False) # String field for poll answer
    votes = db.Column(db.Integer, index=False, unique=False) # Number of votes

    def __repr__(self):
        return f'<Poll_id: {self.poll_id} Option id: {self.id}, answer: {self.answer}, votes: {self.votes}>'

# Declaration of IP_check model
class IP_check(db.Model):
    id = db.Column(db.Integer, primary_key=True) # ID
    ip = db.Column(db.String(32), index=True, unique=False) # IP from which was already voted
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id')) # Foreign key for which poll it was voted
    option_id = db.Column(db.Integer, db.ForeignKey('poll_option.id')) # Foreign key for which poll option it was voted - For future use like changing votes

# Declaration of function that handles adding polls with options
def add_poll_func(title, user_id, poll_private, poll_verification, options):
    if title != None and user_id != None and options != None and poll_private != None and poll_verification != None: #check if everything was passed
        new_url = url_generator() # generate new url
        while Poll.query.filter_by(url=new_url).first() is not None: # check if there is no duplicate url
            new_url = url_generator()
        new_poll = Poll(title=title, user_id=user_id, url=new_url, private=poll_private, is_active=True, verification=poll_verification) # create new Poll object
        db.session.add(new_poll)
        db.session.flush() # Flush to generate ID
        options_list = options.split("\n") # options from field splitted to separate strings by new line
        for option in options_list:
            poll_option = Poll_option(poll_id=new_poll.id,
                                      user_id=user_id,
                                      answer=option,
                                      votes=0) # for each option create new object
            db.session.add(poll_option)
            db.session.flush() # and add it to database
        db.session.commit()


#  Declaration of Function that returns JSON of Polls which can take User id or Poll id, or nothing (then it will get only public polls)
def get_polls_json(user_id=None, poll_id=None):
    polls_json = {}
    if user_id is not None: # If user is specified
        polls = Poll.query.filter_by(user_id=user_id).all()
        options = Poll_option.query.filter_by(user_id=user_id).all()
        for poll in polls:
            option_list = []
            for option in options:
                if option.poll_id == poll.id:
                    option_d = {
                        "id": option.id,
                        "answer": option.answer,
                        "votes": option.votes
                    }
                    option_list.append(option_d)
            polls_json[poll.id] = {
                "title": poll.title,
                "user_id": poll.user_id,
                "url": poll.url,
                "private": poll.private,
                "is_active": poll.is_active,
                "verification": poll.verification,
                "options": option_list
            }
    elif poll_id is not None: # If poll_id is specified
        poll = Poll.query.filter_by(id=poll_id).first()
        options = Poll_option.query.filter_by(poll_id=poll_id).all()
        option_list = []
        for option in options:
            if option.poll_id == poll.id:
                option_d = {
                    "id": option.id,
                    "answer": option.answer,
                    "votes": option.votes
                }
                option_list.append(option_d)
        polls_json[poll.id] = {
            "title": poll.title,
            "user_id": poll.user_id,
            "url": poll.url,
            "private": poll.private,
            "is_active": poll.is_active,
            "verification": poll.verification,
            "options": option_list
        }
    else: # If nothing is specified, gets all polls which are not private
        polls = Poll.query.all()
        options = Poll_option.query.all()
        for poll in polls:
            if poll.private == False:
                option_list = []
                for option in options:
                    if option.poll_id == poll.id:
                        option_d = {
                            "id" : option.id,
                            "answer" : option.answer,
                            "votes" : option.votes
                        }
                        option_list.append(option_d)
                polls_json[poll.id] = {
                    "title": poll.title,
                    "user_id": poll.user_id,
                    "url": poll.url,
                    "private": poll.private,
                    "is_active": poll.is_active,
                    "verification": poll.verification,
                    "options": option_list
                }
    return json.dumps(polls_json)

# function to get option answers into list (used for generating chart in template)
def get_poll_options_labels(poll_id):
    if poll_id is not None: # poll_id validator
        poll = Poll.query.filter_by(id=poll_id).first()
        options = Poll_option.query.filter_by(poll_id=poll_id).all()
        option_labels_list = []
        for option in options:
            if option.poll_id == poll.id:
                option_labels_list.append(option.answer)
        return option_labels_list


# function to get option votes into list (used for generating chart in template)
def get_poll_options_votes(poll_id):
    if poll_id is not None:  # poll_id validator
        poll = Poll.query.filter_by(id=poll_id).first()
        options = Poll_option.query.filter_by(poll_id=poll_id).all()
        option_votes_list = []
        for option in options:
            if option.poll_id == poll.id:
                option_votes_list.append(option.votes)
        return option_votes_list
