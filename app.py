import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

# Αρχικοποίηση εφαρμογής Flask
app = Flask(__name__)

# Διαμόρφωση session - χρήση ρυθμίσεων από: https://cs50.harvard.edu/x/2024/notes/9/#session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Σύνδεση με την βάση δεδομένων
con = sqlite3.connect("data.db", check_same_thread=False)
cur = con.cursor()


# Λειτουργία Αρχικής Σελίδας
@app.route("/", methods=["GET", "POST"])
def index():
    '''Αρχική σελίδα'''

    # Εύρεση username από την βάση δεδομένων, με βάση το μοναδικό αναγνωριστικό του (id) στη συνεδρία (session)
    res = cur.execute("SELECT username FROM users WHERE id = ?", (session.get("id"),))
    username = res.fetchone()
    if not username:
        username = ""
    else:
        username = username[0]

    # Φόρτωση αρχικής ιστοσελίδας index.html
    return render_template("index.html", username=username)


# Λειτουργία Εγγραφής Χρήστη
@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Εγγραφή Χρήστη"""

    # Επιβεβαίωση πως ο χρήστης δεν είναι ήδη συνδεδεμένος, εμφάνιση σφάλματος σε αυτήν την περίπτωση
    if session.get("id"):
        flash("To create a new account, log out of your current one")
        return error(4)
    
    # Kαθαρισμός του session
    session.clear()

    # Επιβεβαίωση χρήσης μεθόδου POST για την συμπλήρωση της φόρμας εγγραφής
    if request.method == "POST":

        # Λήψη εισόδου χρήστη στην φόρμα εγγραφής (αγνοώντας κενούς χαρακτήρες πριν και μετά)
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        pconfirm = request.form.get("pconfirm").strip()

        # Επιβεβαίωση εισαγωγής ονόματος χρήστη, εμφάνιση σφάλματος αν το πεδίο κενό
        if not username:
            flash("Missing username")
            return error(1)

        # Επιβεβαίωση εισαγωγής κωδικού πρόσβασης, εμφάνιση σφάλματος αν το πεδίο κενό
        elif not password:
            flash("Missing password")
            return error(1)
        
        # Επιβεβαίωση επαλήθευσης κωδικού στα 2 πεδία, εμφάνιση σφάλματος αν οι κωδικοί δεν ταυτίζονται
        elif not pconfirm == password:
            flash("Passwords don't match, try again")
            return error(1)
        
        # Επιβεβαίωση πως ο κωδικός είναι τουλάχιστον 6 χαρακτήρες, εμφάνιση σφάλματος αν όχι
        if len(password) < 6:
            flash("Password must be at least 6 characters long")
            return error(1)

        # Κωδικοποίηση (hash) του κωδικού πρόσβασης του χρήστη πριν την είσοδο στην βάση δεδομένων
        hash = generate_password_hash(password)

        # Έλεγχος για την ύπαρξη άλλου λογαριασμού με το ίδιο όνομα, εμφάνιση σφάλματος αν αυτό ισχύει
        search = cur.execute("SELECT 1 FROM users WHERE username = ?", (username, ))
        if search.fetchone():
            flash("Username already exists, try another one")
            return error(1)
        
        # Είσοδος του νέου λογαριασμού στην βάση δεδομένων
        cur.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (username, hash))
        con.commit()

        # Διατήρηση αναγνωριστικού χρήστη (id) στην συνεδρία 
        res = cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        session["id"] = res.fetchone()[0]

        # Εμφάνιση μηνύματος επιτυχίας και ανακατεύθυνση στην αρχική σελίδα
        flash('You have successfully registered, redirecting to main page...')
        return redirect("/")

    # Χρήση μεθόδου GET
    else:
        # Φόρτωση σελίδας εγγραφής
        return render_template("signup.html")


# Λειτουργία Εισόδου Χρήστη
@app.route("/login", methods=["GET", "POST"])
def login():
    """Σύνδεση Χρήστη σε λογαριασμό"""

    # Επιβεβαίωση πως ο χρήστης δεν είναι ήδη συνδεδεμένος, εμφάνιση σφάλματος σε αυτήν την περίπτωση
    if session.get("id"):
        flash("To create a new account, log out of your current one")
        return error(4)
    
    # Kαθαρισμός του session
    session.clear()

    # Επιβεβαίωση χρήσης μεθόδου POST για την συμπλήρωση της φόρμας εισόδου
    if request.method == "POST":

        # Λήψη εισόδου χρήστη από τα πεδία στην φόρμα εγγραφής (αγνοώντας κενούς χαρακτήρες πριν και μετά)
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        # Επιβεβαίωση εισαγωγής ονόματος χρήστη, εμφάνιση σφάλματος αν το πεδίο κενό
        if not username:
            flash("Must provide username")
            return error(2)

        # Επιβεβαίωση εισαγωγής κωδικού πρόσβασης, εμφάνιση σφάλματος αν το πεδίο κενό
        elif not password:
            flash("Must provide password")
            return error(2)

        # Έυρεση ονόματος χρήστη στη βάση δεδομένων
        res = cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        pwd = res.fetchone()

        # Αν το όνομα που πληκτρολογήθηκε στην φόρμα δεν υπάρχει στην βάση, εμφάνιση σφάλματος
        if pwd == None:
            flash(f"Invalid username")
            return error(2)

        # Έλεγχος κωδικού, εμφάνιση σφάλματος αν αυτός λανθασμένος
        if not check_password_hash(pwd[2], password):
            flash(f"Invalid credentials")
            return error(2)

        # Διατήρηση αναγνωριστικού χρήστη (id) στην συνεδρία 
        session["id"] = pwd[0]

        # Εμφάνιση μηνύματος επιτυχίας και ανακατεύθυνση στην αρχική σελίδα
        flash('You have successfully logged in, redirecting to main page...')
        return redirect("/")

    # Χρήση μεθόδου GET
    else:
        # Φόρτωση σελίδας εγγραφής
        return render_template("login.html")
    

# Λειτουργία αποσύνδεσης συνδεδεμένου χρήστη
@app.route("/logout")
def logout():
    '''Αποσύνδεση χρήστη'''

    # Έλεγχος πως ο χρήστης είναι ήδη συνδεδεμένος
    if session.get("id"):

        # Καθαρισμός session
        session.clear()
        flash("You have logged out of your account, redirecting to main page...")
    
    # Επιστροφή στην αρχική σελίδα
    return redirect("/")


# Λειτουργία διαγραφής λογαρισμού
@app.route("/deleteacc", methods=["GET", "POST"])
def deleteacc():
    '''Διαγραφή λογαριασμού'''

    # Ανάκτηση αναγνωριστικού χρήστη απ' τη συνεδρία
    user_id = session.get("id")

    # Επιβεβαίωση πως ο χρήστης συνδεδεμένος
    if user_id:
        # Διαγραφή λογαριασμού από τη βάση δεδομένων
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        con.commit()

        # Καθαρισμός session
        session.clear()

        # Εμφάνιση μηνύματος επιτυχίας διαγραφής του λογαριασμού
        flash("You have succesfully deleted your account, redirecting to main page...")
    
    # Ανακατεύθυνση στην αρχική σελίδα
    return redirect("/")


# Λειτουργία αλλαγής κωδικού πρόσβασης χρήστη
@app.route("/changepwd", methods=["GET", "POST"])
def changepwd():    
    '''Αλλαγή κωδικού πρόσβασης'''

    # Επιβεβαίωση χρήσης μεθόδου POST για την συμπλήρωση της φόρμας εισόδου
    if request.method == "POST":

        # Ανάκτηση αναγνωριστικού χρήστη απ' τη συνεδρία
        user_id = session.get("id")

        # Έλεγχος πως ο χρήστης είναι ήδη συνδεδεμένος
        if user_id:   

            # Λήψη εισόδου χρήστη από τα πεδία στην φόρμα αλλαγής κωδικού (αγνοώντας κενούς χαρακτήρες πριν και μετά)
            oldpass = request.form.get("oldpass").strip()
            newpass = request.form.get("newpass").strip()
            pconfirm = request.form.get("pconfirm").strip()

            # Επιβεβαίωση εισαγωγής κωδικού πρόσβασης, εμφάνιση σφάλματος αν το πεδίο κενό
            if not oldpass:
                flash("Missing old password")
                return error(5)

            # Επιβεβαίωση εισαγωγής νέου κωδικού πρόσβασης στη φόρμα, εμφάνιση σφάλματος αν το πεδίο κενό
            elif not newpass:
                flash("Missing new password")
                return error(5)
            
            # Επιβεβαίωση επαλήθευσης νέου κωδικού στα 2 πεδία, εμφάνιση σφάλματος αν οι κωδικοί δεν ταυτίζονται
            elif not pconfirm == newpass:
                flash("Passwords don't match, try again")
                return error(5)
            
            # Επιβεβαίωση πως ο κωδικός είναι τουλάχιστον 6 χαρακτήρες, εμφάνιση σφάλματος αν όχι
            if len(newpass) < 6:
                flash("Password must be at least 6 characters long")
                return error(5)
            
            # Εύρεση τρέχοντος κωδικού
            res = cur.execute("SELECT hash FROM users WHERE id = ?", (user_id,))
            verif = res.fetchone()
            if verif == None:
                return error(5)
            
            # Αν ο κωδικός που εισήγαγε ο χρήστης ως τον τρέχων κωδικό του δεν επαληθεύεται από την βάση δεδομένων, εμφάνιση σφάλματος 
            if not check_password_hash(verif[0], oldpass):
                flash("Current password entered was invalid")
                return error(5)
            
            # Ανανέωση του παλαιού κωδικού στην βάση με τον νέο κωδικοποιημένο κωδικό που εισήγαγε ο χρήστης στη φόρμα αλλαγής κωδικού
            cur.execute("UPDATE users SET hash = ? WHERE id = ?", (generate_password_hash(newpass), user_id))
            con.commit()

            # Εμφάνιση μηνύματος επιτυχίας κατά την αλλαγή του κωδικού
            flash("You have successfully updated your password, redirecting to main page...")
        
        # Ανακατεύθυνση στην αρχική σελίδα
        return redirect("/")
    
    # Χρήση μεθόδου GET
    else:
        # Φόρτωση σελίδας αλλαγής κωδικού
        return render_template("changepwd.html")


# Κώδικας διαχείρισης σφαλμάτων, πηγές: https://www.reddit.com/r/cs50/comments/azzmhb/finance_buy_500_internal_server_error/, https://stackoverflow.com/questions/29332056/global-error-handler-for-any-exception
# --------------------Aρχή παράθεσης κώδικα(αλλαγμένου για τις ανάγκες της τρέχουσας εφαρμογής)----------------------------
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return error(3, e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# ----------------------------------------------------Τέλος παράθεσης κώδικα----------------------------------------------


def error(source, name="", code=200):
    '''Διαχείριση σφαλμάτων'''

    # Με βάση την προέλευση του σφάλματος, πέρασμα του αντίστοιχου μηνύματος στην ιστοσελίδα
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

    # Φόρτωση ιστοσελίδας με το κατάλληλο μήνυμα
    return render_template("error.html", action=action)


if __name__=="__main__":
    app.run()
