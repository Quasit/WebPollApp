from logging import PlaceHolder
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo

from models import User

# registration form declaration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password',
                              validators=[DataRequired(),
                                          EqualTo('password')])
    submit = SubmitField('Register')

    #check for duplicate username
    def validate_user_id(self, user_id):
        user = User.query.filter_by(id=user_id.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    #check for duplicate emails
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


# Login form declaration
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


# Poll creation form declaration
class PollForm(FlaskForm):
    poll_verification_choices=['Cookie check', 'IP check', 'None']
    title = StringField('Title', validators=[DataRequired()])
    poll_options = TextAreaField('Poll Options', validators=[DataRequired()])
    poll_private = BooleanField('Private Poll - can be only accessed by link')
    poll_verification = SelectField('Poll duplicate checking', choices=poll_verification_choices, validators=[DataRequired()])
    submit = SubmitField('Post')