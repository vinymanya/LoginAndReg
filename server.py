from flask import Flask, render_template, request,redirect, flash, session, url_for
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = "W12Zr47j\3yX R~X@Hu0|q\9!jmM]Lwf/,?KTW%"
EMAIL_REGX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
mysql = MySQLConnector(app, "loginAndRegdb")
bcrypt = Bcrypt(app)

@app.route("/")
def index():
	#just render template: the login and the Registration form
	return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
	#validation process
	if len(request.form["first_name"]) < 1 and len(request.form["last_name"]) < 1:
		flash("name cannot be empty! and name must be at least 2 characters", "error")
		return redirect("/")
	if not EMAIL_REGX.match(request.form["email"]):
		flash("Invalid email address!", "error")
		return redirect("/")
	if len(request.form["password"]) < 8:
		flash("password must be at leat 8 characters!!!", "error")
		return redirect("/")
	elif len(request.form["password"]) != len(request.form["pw_con"]):
		flash("Password doesn't match!!!", "error")
		return redirect("/")
	#password Encryption process
	else:
		password = request.form["password"]
		pw_hash = bcrypt.generate_password_hash(password)
	#database insertion
	query = "INSERT INTO users(first_name, last_name, email, password, confirmation_password, created_at, updated_at) VALUES(:fn, :ln, :email, :pw, :pwc, NOW(), NOW())"
	data = {
		"fn": request.form["first_name"],
		"ln": request.form["last_name"],
		"email": request.form["email"],
		"pw": pw_hash,
		"pwc": pw_hash
	}
	#keeping track of the user:
	user_id = mysql.query_db(query, data)
	session["user_id"] = user_id
	return redirect("/success")

@app.route("/success")
def success():
	return render_template("success.html")

@app.route("/login", methods=["POST"])
def login():
	#handle the login process
	# username = request.form["first_name"]
	username = request.form["first_name"]
	password = request.form["password"]
	query = "SELECT * FROM users WHERE first_name = :username AND password = :pw LIMIT 1"
	data = {
		'username': username,
		'pw': password
	}
	result = mysql.query_db(query, data) # ckeck_user is holding onto a list [] or [{}]
	print result
	if result: # we are checking to see if we have a user with that username and pw.
		if bcrypt.check_password_hash(result[0]['pw_hash'], password ):
			return redirect(url_for('dashboard'))
		else:
			flash("Invalid Username or Password!!!")
			return redirect("/")
	return redirect("/")

@app.route("/dashboard")
def dashboard():
	return render_template("dashboard.html")

app.run(debug=True)