from datetime import date, datetime
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from typing import List
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import os
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

# Documentation
# Macros (to render): https://bootstrap-flask.readthedocs.io/en/stable/basic/#macros
# Python Decorators: https://docs.python.org/3/glossary.html#term-decorator
# Flask Python Decorators: https://flask.palletsprojects.com/en/2.3.x/patterns/viewdecorators/
# 'absort()' function (quick way to return HTTP errors): https://flask.palletsprojects.com/en/2.3.x/api/#flask.abort
# One-to-Many Relationship Database (User create many BlogPost):
# https://docs.sqlalchemy.org/en/20/orm/basic_relationships.html#one-to-many
# Basic Relationship (Parent-Child) SQLAlchemy: https://docs.sqlalchemy.org/en/20/orm/basic_relationships.html
# CKEditor Documentation: https://flask-ckeditor.readthedocs.io/en/latest/basic.html
# Gravatar Images (to provide an avatar image for blog commenters): https://gravatar.com/
# Gravatar Documentation: https://docs.gravatar.com/
# Flask Gravatar Tutorial: https://flask-gravatar.readthedocs.io/en/latest/

MY_EMAIL = os.environ.get("EMAIL")
PASSWORD = os.environ.get("PASSWORD")
DESTINATION_EMAIL = os.environ.get("DESTINATION_EMAIL")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

# CONFIGURE FLASK-LOGIN
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE USER TABLE FOR ALL REGISTERED USERS IN DATABASE (WITH 'USERMIXIN')
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    # *******Add parent relationship to BlogPost******* #
    posts = relationship("BlogPost", back_populates="author")

    # *******Add parent relationship to Comment******* #
    comments = relationship("Comment", back_populates="comment_author")


# CREATE BLOG TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # *******Add child relationship to User******* #
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # ***************Parent Relationship to Comment************* #
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    posted_time = db.Column(db.DateTime, nullable=False)

    # *******Add child relationship to User******* #
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # *******Add child relationship to BlogPost******* #
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


# To allow the user who commented to delete the comment
def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        user = db.session.execute(db.select(Comment).where(Comment.author_id == current_user.id)).scalar()
        if not current_user.is_authenticated or current_user.id != user.author_id:
            return abort(403)
        return function(*args, **kwargs)
    return check


# To add time in comment section
def calculate_time_difference(posted_time):
    current_time = datetime.now()
    time_difference = current_time - posted_time

    # Extract days, hours, and minutes
    days = time_difference.days

    # 'divmod' divide 'time_difference.seconds' by 3600 and save the answer as a tuple, with the whole number and
    # remainder as hours and minutes(remainder) respectively.
    # The same goes for the second tuple. Only the remainder ('_'), which is the seconds, is not needed.
    hours, remainder = divmod(time_difference.seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    if days > 0:
        return f"{days} days ago"
    elif hours > 0:
        return f"{hours} hours ago"
    elif minutes > 0:
        return f"{minutes} minutes ago"
    else:
        return "just now"


# For adding profile images to the comment section
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if user email is already present in the database.
        email = form.email.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            # Means user already has an account
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        # If user hasn't had an account
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8  # Salting
        )
        # Storing the hashed password in our database
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )

        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, current_user=current_user)


# Retrieve a user from the database based on their email.
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find user by email entered.
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Check stored password hash against entered password hashed.
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:  # OR 'if check_password_hash(user.password, password):'
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        # Only allow logged-in users to comment on posts
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                text=form.comment.data,
                comment_author=current_user,
                parent_post=requested_post,
                posted_time=datetime.now()
            )
            db.session.add(new_comment)
            db.session.commit()

    # Tracing the days, hours and minutes each comment is made
    # List of comments with the same post_id
    comments = Comment.query.filter_by(post_id=post_id).all()

    # Updating the time and turning it to list. Note: this doesn't affect the data(time) in posted_time in Comment query
    the_time = []
    for comments_time in comments:
        print(comments_time.posted_time)
        time = calculate_time_difference(comments_time.posted_time)
        the_time.append(time)
    print(the_time)

    return render_template("post.html", post=requested_post, current_user=current_user, form=form, posted_time=the_time)


# Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# Allow the user who commented to delete the comment
@app.route("/delete/comment/<int:comment_id>/<int:post_id>")
@only_commenter
def delete_comment(post_id, comment_id):
    post_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == 'POST':
        data = request.form
        send_email(data["name"], data["email"], data["phone"], data["message"])
        return render_template("contact.html", msg_sent=True, current_user=current_user)
    else:
        return render_template("contact.html", current_user=current_user)


def send_email(name, email, phone, message):
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(user=MY_EMAIL, password=PASSWORD)
        connection.sendmail(
            from_addr=MY_EMAIL,
            to_addrs=DESTINATION_EMAIL,
            msg=f"Subject:New Message\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage:{message}")


if __name__ == "__main__":
    app.run(debug=False, port=5002)
