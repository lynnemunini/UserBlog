from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# To use gravatar images
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', "sqlite:///blog.db").replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
# Configure for login object for login
login_manager.init_app(app)

##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
        
    #This will act like a List of BlogPost objects attached to each User. 
    #The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
db.create_all()

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    #Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    blog_comments = relationship("Comment", back_populates="post")
db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    blog_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="blog_comments")
db.create_all()

##WTForm
class RegisterForm(FlaskForm):
    name = StringField("Your name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


# Admin decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            id = current_user.id
        except: 
            id = None
        if id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Create a user_loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    try:
        id = current_user.id
    except:
        id = None
        
    return render_template("index.html", all_posts=posts, id=id)


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = request.form.get('name')
        email = request.form.get('email')
        # Check database for email address
        user = User.query.filter_by(email=email).first() 
        if user:
            flash("You have an existing account. Login instead.")
            return redirect(url_for("login"))
        else:
                password = request.form.get('password')
                password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
                new_user = User(email=email, password = password, name = name)
                db.session.add(new_user)
                db.session.commit()
                #Log in and authenticate user after adding details to database.
                login_user(new_user)
                return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password_put = request.form.get('password')
        user = User.query.filter_by(email=email).first() 
        try:
            password_match = check_password_hash(user.password, password_put)
        except AttributeError:
            flash("The email does not exist. Please try again.")
            return redirect(url_for("login"))
        else:
            if password_match == False:
                flash("Incorrect password")
                return redirect(url_for("login")) 
            elif password_match:
                #Log in and authenticate user.
                login_user(user)
                return redirect(url_for("get_all_posts"))   
    return render_template("login.html", logged_in=current_user.is_authenticated, form=form)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()

    try:
        id = current_user.id
    except:
        id = None

    if form.validate_on_submit():
        if current_user.is_authenticated:
            text = request.form.get("comment")
            new_comment = Comment(
                text=text,
                author_id=current_user.id,
                blog_id=post_id
                )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You have to be logged in to make a comment.")
            return redirect(url_for('login'))
        
    requested_post = BlogPost.query.get(post_id)
    post_comments = Comment.query.filter_by(blog_id=post_id).all()
    print(post_comments)
    return render_template("post.html", post=requested_post, id=id, form=form, comments=post_comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route('/new-post', methods=["GET","POST"])
# Ensure that the admin is logged in and authenticated before calling the actual view
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
        return render_template("make-post.html", form=form, logged_in=True)

@app.route("/edit-post/<int:post_id>")
# Ensure that the admin is logged in and authenticated before calling the actual view
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

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
# Ensure that the admin is logged in and authenticated before calling the actual view
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # host='0.0.0.0', port=5000
    app.run(debug=True)
