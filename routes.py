from flask import make_response, request, render_template, flash, redirect, url_for
from werkzeug.urls import url_parse
from flask_login import current_user, login_user, logout_user, login_required
import json

from main import app, db, login_manager
from models import IP_check, Poll_option, User, Poll, add_poll_func, get_polls_json, get_ip, add_ip, get_poll_options_labels, get_poll_options_votes
from forms import PollForm, RegistrationForm, LoginForm

# Login manager - User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

# User logout handler route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# User Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


# Single Poll route - accessed by short url attached to Poll model
@app.route('/poll/<poll_url>', methods=['GET', 'POST'])
def poll(poll_url):
    # First getting poll object from database by it's url, then set the owner object by user_id
    # owner variable is used in template to check if logged user is poll owner
    # poll variable is used to check it's verification method, then it checks if user already voted.
    # If so voted variable is set either True or False
    # Then get poll to JSON using get_poll_json function - used to display poll in template
    # poll_labels and poll_votes variables are used to generate pie diagram in template
    poll = Poll.query.filter_by(url=poll_url).first()
    owner = User.query.filter_by(id=poll.user_id).first().username
    polls = json.loads(get_polls_json(poll_id=poll.id))
    poll_labels = get_poll_options_labels(poll.id)
    poll_votes = get_poll_options_votes(poll.id)
    if polls is None:
        polls = {}
    if poll.verification == 'Cookie check': # if cookie verification, pulls cookies, split it to list, checks if poll id is in list, sets voted variable and renders template
        poll_cookie_list = list(map(int, request.cookies.get('voted-polls', '').split()))
        if poll.id in poll_cookie_list:
            voted = True
        else:
            voted = False
        return render_template('poll.html', poll_url=poll_url, polls=polls, voted=voted, poll_labels=poll_labels, poll_votes=poll_votes, owner=owner)
    elif poll.verification == 'IP check':  # if IP verification, checks database for ip and poll.id, sets voted variable and renders template
        user_ip = get_ip()
        if IP_check.query.filter_by(poll_id=poll.id, ip=user_ip).first() is not None:
            voted = True
        else:
            voted = False
        return render_template('poll.html', poll_url=poll_url, polls=polls, voted=voted, poll_labels=poll_labels, poll_votes=poll_votes, owner=owner)
    elif poll.verification == 'None':  # if None verification is set, just sets voted variable to False and renders template
        verif = 'None'
        return render_template('poll.html', poll_url=poll_url, polls=polls, voted=False, poll_labels=poll_labels, poll_votes=poll_votes, owner=owner, verif=verif)


# Adding poll route
@app.route('/add_poll', methods=['GET', 'POST'])
@login_required
def add_poll():
    # Gets user (for its id), and checks if form is posted
    # Then it runs add_poll_func function with all needed parameters
    # Gets new poll url and redirects to new poll
    user = User.query.filter_by(username=current_user.username).first()
    form = PollForm()
    if request.method == 'POST' and form.validate():
        add_poll_func(title=form.title.data,
                 user_id=user.id,
                 poll_private=form.poll_private.data,
                 poll_verification=form.poll_verification.data,
                 options=form.poll_options.data)
        new_poll = Poll.query.filter_by(title=form.title.data).first()
        new_url = new_poll.url
        return redirect(url_for('poll', poll_url=new_url))
    else:
        flash(form.errors)
    return render_template('add_poll.html', username=user.username, form=form)

# User page route - gets the user object by it's username, then runs get_polls_json for all polls with user_id equal to user and renders template
@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first()
    polls = json.loads(get_polls_json(user.id))
    if polls is None:
        polls = {}
    return render_template('user.html', username=user.username, polls=polls)


# Index page which simply runs get_polls_json without parameters to get all public polls and renders template
@app.route('/')
def index():
    polls = json.loads(get_polls_json())
    if not polls:
        polls={}
    return render_template('landing_page.html', polls=polls)

# vote button route - checks poll verification options, and then accordingly adds poll id to ip or cookies and increases the votes and renders template
@app.route('/vote/<poll_url>/<int:option_id>')
def vote(poll_url, option_id):
    # gets poll object from database by poll_url
    # checks it's verification method
    # verify if already voted
    # adds vote and set as voted
    # renders template
    poll = Poll.query.filter_by(url=poll_url).first()
    if poll.verification == 'Cookie check':
        voted = list(map(int, request.cookies.get('voted-polls', '').split())) # pulling poll_ids from cookies, splits them and puts in list
        if poll.id not in voted: #checks if current poll_id isn't already in list
            option = Poll_option.query.get(option_id) # then gets the option object by it's id
            option.votes = option.votes + 1  # increases votes
            db.session.commit()
            voted.append(poll.id)  # add poll_id to cookies list
        voted_str=''
        for id in voted: voted_str+= str(id) + ' ' # now preparing new cookie from existing list
        resp = make_response(
            redirect(url_for('poll', poll_url=poll_url, voted=voted)))
        resp.set_cookie('voted-polls', str(voted_str)) # and reloading page with setting new cookie
        return resp
    elif poll.verification == 'IP check':
        ip = get_ip() # getting user ip
        if IP_check.query.filter_by(ip=ip, poll_id=poll.id).first() is None: # checks if user ip isn't already in database with current poll_id
            option = Poll_option.query.get(
                option_id)  # then gets the option object by it's id
            option.votes = option.votes + 1  # increases votes
            add_ip(poll_id=poll.id, option_id=option.id) #creates new IP_check entry for database
            db.session.commit()
            return redirect(url_for('poll', poll_url=poll_url)) # and reloads the page
    elif poll.verification == 'None':
        option = Poll_option.query.get(option_id) # No verification needed, so just get option object by it's id
        option.votes = option.votes + 1  # increase votes
        db.session.commit()
        return redirect(url_for('poll',
                                poll_url=poll_url))  # and reloads the page


# Route for closing poll button
@app.route('/user/<username>/close_poll/<int:poll_id>')
def close_poll(username, poll_id):
    poll = Poll.query.filter_by(id=poll_id).first()
    poll.is_active = False
    db.session.commit()
    return redirect(url_for('user', username=username))


# Route for opening poll button
@app.route('/user/<username>/open_poll/<int:poll_id>')
def open_poll(username, poll_id):
    poll = Poll.query.filter_by(id=poll_id).first()
    poll.is_active = True
    db.session.commit()
    return redirect(url_for('user', username=username))


# Route for making poll public button
@app.route('/user/<username>/make_public/<int:poll_id>')
def make_public(username, poll_id):
    poll = Poll.query.filter_by(id=poll_id).first()
    poll.private = False
    db.session.commit()
    return redirect(url_for('user', username=username))


# Route for making poll private button
@app.route('/user/<username>/make_private/<int:poll_id>')
def make_private(username, poll_id):
    poll = Poll.query.filter_by(id=poll_id).first()
    poll.private = True
    db.session.commit()
    return redirect(url_for('user', username=username))

# Route for deleting poll button
@app.route('/user/<username>/delete_poll/<int:poll_id>')
def delete_poll(username, poll_id):
    poll = Poll.query.filter_by(id=poll_id).first()
    db.session.delete(poll)
    db.session.commit()
    return redirect(url_for('user', username=username))