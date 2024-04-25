from collections.abc import Sequence
from typing import Any, Mapping
from flask import Flask, render_template,redirect,url_for,session,flash
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired,Email,ValidationError 
import bcrypt
import pymssql

app = Flask(__name__)

app.config ['SERVER'] = '192.168.1.16'
app.config['DATABASE'] = 'PunchData'
app.config['USERNAME'] = 'palvish'
app.config['PASSWORD'] = 'palvish'
app.secret_key=' '

def get_database_connection():
    return pymssql.connect(server=app.config['SERVER'], user=app.config['USERNAME'], password=app.config['PASSWORD'], database=app.config['DATABASE'])



class RegisterForm(FlaskForm):
    name=StringField("Name",validators=[DataRequired()])
    email=StringField("Email",validators=[DataRequired(),Email()])
    password=PasswordField("Password",validators=[DataRequired()])
    submit=SubmitField("Register")

    def validate_email(self,field):
         with get_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM User_data WHERE email=%s", ( field.data))
            User_data=cursor.fetchone()
            conn.commit()
            if User_data:
                raise ValidationError('email already used')
        

class LoginForm(FlaskForm):
    email=StringField("Email",validators=[DataRequired(),Email()])
    password=PasswordField("Password",validators=[DataRequired()])
    submit=SubmitField("submit")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register",methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        name=form.name.data
        email=form.email.data
        password=form.password.data

        hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        #data base
        with get_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO User_data (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
            conn.commit()

        return redirect(url_for('login'))

    return render_template("register.html",form=form)

@app.route("/login",methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        email=form.email.data
        password=form.password.data

        #data base
        with get_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM User_data WHERE email=%s", ( email))
            User_data=cursor.fetchone()
            conn.commit()
        if User_data and bcrypt.checkpw(password.encode('utf-8'),User_data[3].encode('utf-8')):
            session['user_id']=User_data[0]
            return redirect(url_for('dashboard'))
        else:
            flash("login failed")
            return redirect(url_for('login'))

    return render_template("login.html",form=form)

@app.route("/dashboard",methods=['GET','POST'])
def dashboard():
    if 'user_id' in session:
        user_id= session['user_id']
        with get_database_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM User_data WHERE id=%s", (user_id))
            User_data=cursor.fetchone()
            conn.commit()

        if user_id:
            return render_template('dashboard.html',user = user_id)
        
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id',None)
    flash("logged out sucessfully")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)