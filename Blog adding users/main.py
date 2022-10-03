from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateRegisterForm, CreateLoginForm, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(id):
    return Users.query.get(id)


# @app.errorhandler(404)
# def not_found(error):
#     return render_template('404.html'), 404
#
#
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.is_anonymous:
            current_user.id = 0
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:
            abort(403)

    return wrapper


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users_data.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship("Users", back_populates="posts")
    comments = relationship("Comment", back_populates="post", primaryjoin="BlogPost.id == Comment.post_id")


class Users(UserMixin, db.Model):
    __tablename__ = "users_data"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    posts = relationship("BlogPost", back_populates="author", primaryjoin="BlogPost.author_id == Users.id")
    comments = relationship("Comment", back_populates="commentator", primaryjoin="Comment.commentator_id == Users.id")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    commentator_id = db.Column(db.Integer, db.ForeignKey("users_data.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    commentator = relationship("Users", back_populates="comments")
    post = relationship("BlogPost", back_populates="comments")


#
# db.create_all()
# db.session.commit()



@app.route('/')
def get_all_posts():
    if current_user.is_anonymous:
        current_user.id = 0
    posts = BlogPost.query.all()
    users = Users.query.all()
    return render_template("index.html", all_posts=posts, all_users=users, logged_in=current_user.is_authenticated,
                           is_admin=(current_user.id == 1))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateRegisterForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if not user:
            hashed_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
            new_user = Users(
                email=form.email.data,  # type: ignore
                name=form.name.data,  # type: ignore
                password=hashed_password  # type: ignore
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            flash("Email already registered", "Error")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = CreateLoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect password", "Error")
                return redirect(url_for("login"))
        else:
            flash("Email not registered", "Error")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    if current_user.is_anonymous:
        current_user.id = 0
    form = CreateCommentForm()
    requested_post = BlogPost.query.get(post_id)
    post_comments = Comment.query.filter_by(post_id=post_id).all()
    if form.validate_on_submit():
        if current_user.is_anonymous:
            flash("Login to comment", "Error")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                text=form.comment.data,
                commentator_id=current_user.id,
                post_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, comments=post_comments, form=form, is_admin=(current_user.id == 1))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
