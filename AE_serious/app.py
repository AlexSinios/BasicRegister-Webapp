import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Configure session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Σύνδεση με την βάση δεδομένων
con = sqlite3.connect("data.db", check_same_thread=False)
cur = con.cursor()


@app.route("/", methods=["GET", "POST"])
def index():
    res = cur.execute("SELECT username FROM users WHERE id = ?", (session.get("id"),))
    username = res.fetchone()
    if not username:
        username = ""
    else:
        username = username[0]

    return render_template("index.html", username=username)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Register user"""

    if session.get("id"):
        flash("To create a new account, log out of your current one")
        return error(4)
    
    # Kαθαρισμός του session
    session.clear()

    # Confirm that POST has been used as opposed to GET
    if request.method == "POST":

        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        pconfirm = request.form.get("pconfirm").strip()

        # Make sure a username was provided
        if not username:
            flash("Missing username")
            return error(1)

        # Make sure a password was provided
        elif not password:
            flash("Missing password")
            return error(1)
        
        elif not pconfirm == password:
            flash("Passwords don't match, try again")
            return error(1)
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long")
            return error(1)

        # # Make sure the passwords match
        # elif not request.form.get("password") == request.form.get("pword2"):
        #     return render_template("error.html")

        # Hash the password for security reasons
        hash = generate_password_hash(password)

        # Extra verification for existing username
        search = cur.execute("SELECT 1 FROM users WHERE username = ?", (username, ))
        if search.fetchone():
            flash("Username already exists, try another one")
            return error(1)
        
        # Insert the new users in the SQL database, hashing the password
        cur.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (username, hash))
        con.commit()

        # Remember the user
        res = cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        session["id"] = res.fetchone()[0]

        # Tell the user that he has successfully registered
        flash('You have successfully registered, redirecting to main page...')
        return redirect("/")

    else:
        return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    if session.get("id"):
        flash("To create a new account, log out of your current one")
        return error(4)
    
    # Kαθαρισμός του session
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        # Ensure username was submitted
        if not username:
            flash("Must provide username")
            return error(2)

        # Ensure password was submitted
        elif not password:
            flash("Must provide password")
            return error(2)

        # Query database for username
        res = cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        pwd = res.fetchone()
        if pwd == None:
            flash(f"Invalid username")
            return error(2)

        # Ensure username exists and password is correct
        if not check_password_hash(pwd[2], password):
            flash(f"Invalid credentials: {check_password_hash(pwd[2], password)}")
            return error(2)
            #return redirect(url_for('error', action = "Invalid credentials"))
        # Remember which user has logged in
        session["id"] = pwd[0]

        # Redirect user to home page
        flash('You have successfully logged in, redirecting to main page...')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
    

@app.route("/logout")
def logout():
    if session.get("id"):
        session.clear()
        flash("You have logged out of your account, redirecting to main page...")
    return redirect("/")


@app.route("/deleteacc", methods=["GET", "POST"])
def deleteacc():
    user_id = session.get("id")
    if user_id:
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        con.commit()
        session.clear()
        flash("You have succesfully deleted your account, redirecting to main page...")
    return redirect("/")


@app.route("/changepwd", methods=["GET", "POST"])
def changepwd():    

    # Confirm that POST has been used as opposed to GET
    if request.method == "POST":

        user_id = session.get("id")

        if user_id:   
            oldpass = request.form.get("oldpass").strip()
            newpass = request.form.get("newpass").strip()
            pconfirm = request.form.get("pconfirm").strip()

            # Make sure a username was provided
            if not oldpass:
                flash("Missing old password")
                return error(5)

            # Make sure a password was provided
            elif not newpass:
                flash("Missing new password")
                return error(5)
            
            elif not pconfirm == newpass:
                flash("Passwords don't match, try again")
                return error(5)
            
            if len(newpass) < 6:
                flash("Password must be at least 6 characters long")
                return error(5)
            
            # Query database for user id
            res = cur.execute("SELECT hash FROM users WHERE id = ?", (user_id,))
            verif = res.fetchone()
            if verif == None:
                return error(5)
            
            if not check_password_hash(verif[0], oldpass):
                flash("Current password entered was invalid")
                return error(5)
            
            cur.execute("UPDATE users SET hash = ? WHERE id = ?", (generate_password_hash(newpass), user_id))
            con.commit()

            flash("You have successfully updated your password, redirecting to main page...")
        return redirect("/")
    
    else:
        return render_template("changepwd.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return error(3, e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


def error(source, name="", code=200):
    if source == 1:
        action = "while registering your account"
    elif source == 2:
        action = "while logging into your account"
    elif source == 4:
        action = ": You are trying to sign up/log in whilst still in an active session. Log out of your current account first. Then"
    elif source == 5:
        action = "while changing your password"
    else: 
        action = f"HTTP CODE {code}: '{name}'"
    return render_template("error.html", action=action)


if __name__=="__main__":
    app.run()
