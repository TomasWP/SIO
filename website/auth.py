from flask import Blueprint, render_template, request, flash

auth = Blueprint('auth', __name__)

@auth.route("/login", methods=['GET', 'POST'])
def login():
    user = request.form.get('user')
    password = request.form.get('password')
    print(user, password)
    if user == 'tomas' and password == '12345':
        flash("Logged in successfully!", category='success')
        return render_template("index.html")
    flash("Incorrect username or password", category='error')
    return render_template("login.html")

@auth.route("/logout")
def logout():
    return "<p>Logout</p>"

@auth.route("/signup", methods=['GET', 'POST'])
def sign_up():
    user = request.form.get('user')
    password = request.form.get('password')
    confirmpassword = request.form.get('confirmpassword')
    print(user, password, confirmpassword)

    if len(str(password)) < 5:
        flash("Password must be at least 5 characters", category='error')
    elif str(password) != str(confirmpassword):
        flash("Passwords don't match", category='error')
    else:
        flash("Account created!", category='success')
        return render_template("index.html")
    return render_template("signup.html")

