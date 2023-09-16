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
    print(user, password)
    if user == 'tomas' and password == '12345':
        flash("Logged in successfully!", category='success')
        return render_template("index.html")
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
    print(username, password, confirmpassword)

    # Check if the requested method is POST
    if request.method == "POST":
        if len(str(password)) < 5:
            flash("Password must be at least 5 characters", category='error')
        elif str(password) != str(confirmpassword):
            flash("Passwords don't match", category='error')
        else:
            # Create the user in the database
            functions.create_user(username, password)
            print("User created with id: " + id)
            flash("Account created!", category='success')
            # Return the login page
            return redirect(url_for("views.login", username=username))
    return render_template("signup.html")