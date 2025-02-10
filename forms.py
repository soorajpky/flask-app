from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, FloatField, DateField
from wtforms.validators import DataRequired, Email, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BoardForm(FlaskForm):
    name = StringField('Board Name', validators=[DataRequired()])
    location_url = StringField('Location URL', validators=[DataRequired()])
    renewal_date = DateField('Renewal Date', format='%Y-%m-%d', validators=[DataRequired()])
    renewal_amount = FloatField('Renewal Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')

class UserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    is_admin = BooleanField('Admin')
    submit = SubmitField('Add User')

