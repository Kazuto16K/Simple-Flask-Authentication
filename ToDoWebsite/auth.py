from flask import Blueprint,render_template,request,flash, redirect, url_for
# BLUEprint means bunch of urls defined
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
import bcrypt
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first() #returns the first user having same email
        if user:
            u_pass = user.password
            if bcrypt.checkpw(password.encode('utf-8'),u_pass):
                flash('Logged in Successfully!', category='success')
                login_user(user,remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password.', category='error')
        else:
            flash('Email doesnt exist', category='error')

    return render_template('login.html', user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')

        elif len(email)<4:
            flash('Your email is too short! Must be greater than 4 characters.' , category='error')
        elif len(firstName) < 2:
            flash('Your name is too short! Must be greater than 2 characters.' , category='error')
        elif password1 != password2 :
            flash('Your passwords don\'t match!' , category='error')
        elif len(password1) < 7:
            flash('Password Size is too Short! must be atleast 7 characters', category='error')
        else:
            new_user = User(email=email, first_name=firstName, password=bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt()))
            db.session.add(new_user)
            db.session.commit()
            login_user(user,remember=True)
            flash('Account Created! ', category='success')

            return redirect(url_for('views.home'))
    return render_template('sign_up.html', user=current_user)