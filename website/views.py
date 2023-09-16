from flask import Blueprint, redirect, render_template, request, flash, url_for
from functions import functions

views = Blueprint('views', __name__)

@views.route('/')
def index():
    return render_template("index.html")

@views.route("/login", methods=['GET', 'POST'])
def login():
    user = request.form.get('user')
    password = request.form.get('password')
    if functions.validate_login(user, password):
        flash("Logged in successfully!", category='success')
        return render_template("index.html")
    else:
        flash("Incorrect username or password", category='error')
    return render_template("login.html")

@views.route("/logout")
def logout():
    return "<p>Logout</p>"

@views.route("/signup", methods=['GET', 'POST'])
def sign_up():
    username = request.form.get('user')
    password = request.form.get('password')
    confirmpassword = request.form.get('confirmpassword')

    # Check if the requested method is POST
    if request.method == "POST":
        # Check if the username already exists
        if functions.search_user_by_username(username):
            flash("Username already exists", category='error')
        elif len(str(password)) < 5:
            flash("Password must be at least 5 characters", category='error')
        elif str(password) != str(confirmpassword):
            flash("Passwords don't match", category='error')
        else:
            # Create the user in the database
            id = functions.create_user(username, password)
            flash("Account created!", category='success')
            # Return the login page
            return render_template("login.html")
    return render_template("signup.html")