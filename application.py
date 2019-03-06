import os
import requests

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from time import gmtime, strftime

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
"""@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response"""


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure the database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

@app.route('/')
@login_required
def index():
   return render_template("index.html")


@app.route('/search',methods=["GET","POST"])
@login_required
def search():
    if  request.method == "POST":
        item = request.form.get("item")
        method = request.form.get("method")
        if method == "all":
            Books = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE name LIKE '%{item}%'").fetchall()
            titles = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE title LIKE '%{item}%'").fetchall()
            isbns = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE isbn LIKE '%{item}%'").fetchall()
            years = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE CAST(year AS TEXT) LIKE '%{item}%'").fetchall()
            return render_template("all.html", books=Books, titles=titles, isbns=isbns, years=years, item=item)
        
        if method == "author":
            Books = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE name LIKE '%{item}%'").fetchall()
            return render_template("result.html", books=Books, item=item)
        
        if method == "title":
            Books = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE title LIKE '%{item}%'").fetchall()
            return render_template("result.html", books=Books, item=item)
        
        if method == "isbn":
            Books = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE isbn LIKE '%{item}%'").fetchall()
            return render_template("result.html", books=Books, item=item)
        
        if method == "year":
            Books = db.execute(f"SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE CAST(year AS TEXT) LIKE '%{item}%'").fetchall()
            return render_template("result.html", books=Books, item=item)    
    else:
        return render_template("search.html")


@app.route('/title')
@login_required
def title():
   titels = db.execute("SELECT title,name,book.id FROM book INNER JOIN author ON book.author_id = author.id ").fetchall()
   return render_template("title.html",titels=titels)

@app.route('/author')
@login_required
def author():
    authors = db.execute("SELECT * FROM author").fetchall()
    return render_template("author.html",authors=authors)



@app.route('/login',methods=["GET","POST"])
def login():
    # Forget any user:
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("please enter your username",403)
        if not request.form.get("password"):
            return apology("please enter your password",403)

        user = db.execute("Select * FROM users WHERE username = :username",{"username":request.form.get("username")}).fetchone()
        names = [username for username in user]
        if len(names) != 3 or not check_password_hash(user.hash, request.form.get("password")):
            return apology("invalid username or password",403)

        session["user_id"] = user.id
        return redirect("/")
    else:
        return render_template("login.html")


@app.route('/logout')
@login_required
def logout():
   session.clear()
   return redirect("/")


@app.route('/register', methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        if not request.form.get("username"):
           return apology("please enter your username",403)
        user = db.execute("SELECT COUNT(*) FROM users WHERE username = :username", {"username":username}).fetchone()
        if user.count > 0:
            return apology("username already existe",403)

        password = request.form.get("password")
        if not request.form.get("password"):
           return apology("please enter your password",403)

        confirmation = request.form.get("confirmation")
        if not request.form.get("confirmation"):
           return apology("please enter your password",403) 

        if password != confirmation :
            return apology("The Password Confirmation must match your Password")

        hashpass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username,hash) VALUES(:username,:hashpass)",{"username":username,"hashpass":hashpass})
        db.commit()
        return redirect("/login")
    else:
        return render_template("register.html")    


@app.route("/pass", methods=["GET", "POST"])
@login_required
def changpassword():
    """Change password"""
    if request.method == "POST":
        password = request.form.get("password")
        if not password:
            return apology("please enter your password")    
        user = db.execute("Select * FROM users WHERE id = :id",{"id":session["user_id"]}).fetchone()
        names = [username for username in user]
        if len(names) != 3 or not check_password_hash(user.hash, request.form.get("password")):
            return apology("invalid username or password",403)

        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")
        if not newpassword:
            return apology("please enter a new password")
        if not confirmation:
            return apology("confirme your password")
        if newpassword != confirmation:
            return apology("The Password Confirmation must match your Password")
        hashpass = generate_password_hash(newpassword, method='pbkdf2:sha256', salt_length=8)
        rows = db.execute("UPDATE users SET hash = :hashpass WHERE id = :id", {"hashpass":hashpass, "id":session["user_id"]})
        db.commit()
        session.clear()
        return render_template("login.html")
    else:
        return render_template("pass.html")

@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    if len(username) > 0:
        rows = db.execute("SELECT COUNT(*) FROM users WHERE username = :username", {"username":username}).fetchone()
        if rows.count > 0:
            return jsonify(False)
        else:
            return jsonify(True)  

@app.route("/connect", methods=["GET"])
def connect():
    """Return true if username and password valid, else false, in JSON format"""
    username = request.args.get("username")
    password = request.args.get("password")
    if len(username) > 0:
        user = db.execute("SELECT * FROM users WHERE username = :username", {"username":username}).fetchone()
        if user is None:
            return jsonify(False)
        names = [username for username in user]
        if len(names) != 3 or not check_password_hash(user.hash, password):
            return jsonify(False)
        else:
            return jsonify(True)


@app.route("/password", methods=["GET"])
@login_required
def password():
    """Return true if password wright, else false, in JSON format"""
    password = request.args.get("password")
    if len(password) > 0:
        user = db.execute("Select * FROM users WHERE id = :id",{"id":session["user_id"]}).fetchone()
        if user is None:
            return jsonify(False)
        names = [username for username in user]
        if len(names) != 3 or not check_password_hash(user.hash,password):
            return jsonify(False)
        else:
            return jsonify(True)

@app.route('/reviews/<int:book_id>')
@login_required
def reviews(book_id):
            review = request.args.get("review")
            time = strftime("%a, %d %b %Y %H:%M:%S", gmtime())
            db.execute("INSERT INTO reviews (user_id,review,time,book_id) VALUES(:user_id,:review,:time,:book_id)",{"user_id":session["user_id"],"review":review,"time":time,"book_id":book_id})
            db.commit()
            return redirect(url_for("book",book_id=book_id))  

   

@app.route('/get/<int:book_id>')
@login_required
def book(book_id):
    book = db.execute("SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE book.id = :id",{"id":book_id}).fetchall()
    reviews = db.execute("SELECT * FROM reviews INNER JOIN users ON reviews.user_id = users.id WHERE book_id = :id",{"id":book_id}).fetchall()
    return render_template("thebook.html", books=book, reviews=reviews, id=book_id)

@app.route('/get/<string:name>')
@login_required
def authorbook(name):
    book_ids = []
    books = db.execute("SELECT * FROM book INNER JOIN author ON book.author_id = author.id WHERE name = :name",{"name":name}).fetchall()
    ids = db.execute("SELECT book.id FROM book INNER JOIN author ON book.author_id = author.id WHERE name = :name",{"name":name}).fetchall()
    for i in ids :
        book_ids.append(i.id)
    return render_template("books.html",books=books ,author=name ,book_ids=book_ids)


@app.route('/api/<isbn>',methods=["GET"])
def api(isbn):
    this = str(isbn)
    book = db.execute("SELECT title,name,year,isbn FROM book INNER JOIN author ON book.author_id = author.id WHERE isbn = :isbn",{"isbn":this}).fetchone()
    if book is None:
        return (jsonify({"error": "Invalid ISBN"}), 404)
    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": "TqZJfIOxMtBi0q572bdg", "isbns": isbn})
    books = res.json()
    count = books["books"][0]["reviews_count"]
    score = books["books"][0]["average_rating"]
    return (jsonify({"book":
        {
            "title": book.title,
            "author": book.name,
            "year": book.year,
            "isbn": book.isbn,
            "review_count": count,
            "average_score": score
        }}), 200)    


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
