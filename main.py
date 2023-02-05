from flask import Flask, render_template, request, url_for, redirect, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from collections import Counter
import re
from pathlib import Path
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/home/ubuntu/AWS/static/files/'
#UPLOAD_FOLDER = 'C:\Users\AbrarAhmed Mohammed\Desktop\CC\AWS'
ALLOWED_EXTENSIONS = {'txt'}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

#db.drop_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    firstname = db.Column(db.String(1000))
    lastname = db.Column(db.String(1000))
    filename = db.Column(db.String(1000))

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            #email=request.form.get('email'),
            #name=request.form.get('name'),
            username=request.form.get('username'),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)

        #return redirect(url_for("secrets"))
        return render_template("userdetails.html")

    return render_template("register.html")

@app.route('/userdetails', methods=["GET", "POST"])
def userdetails():
    if request.method == "POST":
        user = User.query.filter_by(username=current_user.username).first()

        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')


        file = request.files['file']
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], current_user.username+'_in_'+file.filename))

        user.firstname = firstname
        user.lastname = lastname
        user.email = email
        user.filename = current_user.username+'_in_'+file.filename
        db.session.commit()

        output_filename = UPLOAD_FOLDER + current_user.filename
        output_filename_mod = output_filename.replace("_in_", "_out_")
        fp = open(output_filename_mod, 'x')
        fp.close()

        login_user(user)
        return redirect(url_for('secrets'))

    return render_template("userdetails.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        # Find user by email entered.
        user = User.query.filter_by(username=username).first()

        if user:
            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('secrets'))
        else:
            return render_template("login.html")

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():

    output_filename = UPLOAD_FOLDER + current_user.filename

    f = open(output_filename, "r")
    docs = f.readlines()
    f.close()

    counter = Counter()
    for i in range(len(docs)):
        counter.update(re.findall('\w+', docs[i]))
    response = []

    for word, count in counter.items():
        response.append('"{}": {}'.format(word, count))

    response_cont = '\n'.join(response)
    print(response_cont)

    output_filename_mod = output_filename.replace("_in_", "_out_")

    fp = open(output_filename_mod, 'w')
    fp.write(response_cont)
    fp.close()

    print('file:///'+output_filename_mod)

    return render_template("secrets.html", firstname=current_user.firstname, lastname=current_user.lastname,
                           email=current_user.email, message=response_cont)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    output_filename = current_user.filename
    output_filename_mod = output_filename.replace("_in_", "_out_")
    print(output_filename_mod)

    file_one= Path(UPLOAD_FOLDER+'output.txt')
    file_one.touch(exist_ok=True)
    # open both files
    with open(UPLOAD_FOLDER+output_filename_mod, 'r') as firstfile, open(UPLOAD_FOLDER+'output.txt','w') as secondfile:
        for line in firstfile:
            secondfile.write(line)

    return send_from_directory('static', filename="files/output.txt", as_attachment=True)

if __name__ == "__main__":
    #app.run(host='0.0.0.0',port=8080)
    #app.run(debug = True)
    app.run(host='0.0.0.0',port=8080)