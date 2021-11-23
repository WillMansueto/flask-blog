from flask import Flask, render_template, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

#Create flask instance
app = Flask(__name__)
# Add Database
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://bob:123pin456pin@localhost/users'
#secret key
app.config['SECRET_KEY'] = "NUTNUTNUT"
# initialize db
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    favorite_color = db.Column(db.String(120))
    # Password
    password_hash = db.Column(db.String(128))
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    
    #Create a String
    def __repr__(self):
        return '<Name %r>' % self.name

# Create Form Class
class PasswordForm(FlaskForm):
    email = StringField("What's your email?", validators=[DataRequired()])
    password_hash = PasswordField("What's your password?", validators=[DataRequired()])
    submit = SubmitField('Submit')

# Create Form Class
class NamerForm(FlaskForm):
    name = StringField("What's your name?", validators=[DataRequired()])
    submit = SubmitField('Submit')

# Create Form Class
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    favorite_color = StringField("Favorite Color")
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Password Must Match!')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

#create a router decorator
@app.route('/')
def index():
    return render_template('index.html')

# localhost:5000/user/bob
@app.route('/user/<name>')
def user(name):
    return render_template('user.html', user_name=name)

# Create Password Test Page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
    email = None
    password = None
    pw_check = None
    passed = None
    form = PasswordForm()
    #validate form:
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        
        #clear the form
        form.email.data = ''
        form.password_hash.data = ''
        
        #Select user by email
        pw_check = Users.query.filter_by(email=email).first()

        #Check hashed password
        passed = check_password_hash(pw_check.password_hash, password)

    return render_template('test_pw.html', email=email, password=password, pw_check=pw_check, passed=passed, form=form)

# Create Name Page
@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None
    form = NamerForm()
    #validate form:
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash('Form Submited Successfully!')

    return render_template('name.html', name=name, form=form)

# Insert User
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hash Password:
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        form.favorite_color.data = ''
        form.password_hash.data = ''

        flash("User Added Successfully!")
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html', form=form, name=name, our_users=our_users)


# Update User:
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        try:
            db.session.commit()
            flash('User Updated Successfully!')
            return render_template('update.html', form=form, name_to_update=name_to_update)
        except:
            db.session.commit()
            flash('Error! Try again...')
            return render_template('update.html', form=form, name_to_update=name_to_update)
    else:
        return render_template('update.html', form=form, name_to_update=name_to_update, id=id)

# Delete User:
@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully!")
        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', form=form, name=name, our_users=our_users)
    except:
        flash("Error! Please, try again!")
        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', form=form, name=name, our_users=our_users)
# Create Custom Error Pages
# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 50

