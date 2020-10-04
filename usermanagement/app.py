from flask import Flask,render_template,request,session,logging,url_for,redirect,flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker
from passlib.hash import sha256_crypt

engine = create_engine("mysql+pymysql://root:admin@localhost/usermanagement")
db = scoped_session(sessionmaker(bind=engine))
app = Flask(__name__)


@app.route("/")
def home():
    return render_template("home.html")

@app.route("/signup", methods=["GET","POST"])
def signup():

    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        secure_password = sha256_crypt.encrypt(str(password))

        if password == confirm:
            db.execute("INSERT INTO user(name, username, password) VALUES(:name, :username, :password)",
                                         {"name" :name, "username" :username, "password" :secure_password})
            db.commit()
            flash("You have registered successfully","danger")
            return redirect(url_for('login'))
        else:
            flash("password does not match","success")
            return render_template('signup.html')

    return render_template("signup.html")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method =="POST":
         username = request.form.get("name")
         password = request.form.get("password")

         usernamedata = db.execute("SELECT username from user WHERE username=:username",{"username":username}).fetchone()
         passworddata = db.execute("SELECT password from user WHERE username=:username",{"username":username}).fetchone()

         if usernamedata is None:
             flash("No username","danger")
             return render_template("login.html")
         else:
             for password_data in  passworddata:
                 if sha256_crypt.verify(passworddata,password_data):
                     session["log"] = True 
                     flash("You are now logged in","success") 
                     return redirect(url_for('company'))
                 else:
                     flash("incorrect password","danger")
                     return render_template("login.html")    

    return render_template("login.html")    

@app.route("/company")
def company(): 
    return render_template("company.html")  
    
@app.route("/logout")
def logout():
    session.clear()
    flash("You are now logged out","success")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.secret_key="It is a secret"
    app.run(debug=True)    