from flask import Flask, render_template, session, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from flask_moment import Moment
from datetime import datetime
import os
import requests
from dotenv import load_dotenv
import random

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'hard to guess string')
bootstrap = Bootstrap(app)
moment = Moment(app)

DEEPSEEK_API_KEY = os.getenv('DEEPSEEK_API_KEY')
API_URL = "https://api.deepseek.com/v1/chat/completions"

class NameForm(FlaskForm):
    name = StringField('What is your name???', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LogingPassForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    name = StringField('Shoppers Name:', validators=[DataRequired(), Length(1, 64),
                                                     Regexp(r'^[A-Za-z\s-]+$', 0,
                                                            'Shoppers names must have only letters, spaces, or hyphens')])
    username = StringField('User ID: ', validators=[DataRequired(), Length(1, 64),
                                                     Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                            'Usernames must have only letters, numbers, dots or underscores')])
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired(),
                                                     EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

class AdminAssignRoleForm(FlaskForm):
    email = SelectField('User Email', choices=[], validators=[DataRequired()])
    role = SelectField('Role', choices=[('shopper', 'Shopper'), ('seller', 'Seller')], validators=[DataRequired()])
    submit = SubmitField('Assign Role')

class AdminAddStoreForm(FlaskForm):
    store_name = StringField('Store Name', validators=[DataRequired()])
    submit = SubmitField('Add Store')

users = {}
user_roles = {} #store user roles
vendors = {
    "Fresh Farms Market": [
        {"name": "Organic Apples", "category": "Fruits"},
        {"name": "Whole Wheat Bread", "category": "Bakery"},
        {"name": "Free-Range Eggs", "category": "Dairy"},
        {"name": "Local Honey", "category": "Pantry"}
    ],
    "Green Grocers Co.": [
        {"name": "Spinach", "category": "Vegetables"},
        {"name": "Carrots", "category": "Vegetables"},
        {"name": "Brown Rice", "category": "Pantry"},
        {"name": "Almond Milk", "category": "Dairy"}
    ],
    "Butcher's Best": [
        {"name": "Beef Steak", "category": "Meat"},
        {"name": "Chicken Breast", "category": "Meat"},
        {"name": "Salmon Fillet", "category": "Seafood"},
        {"name": "Pork Chops", "category": "Meat"}
    ],
    "Daily Dairy Delights": [
        {"name": "Cheddar Cheese", "category": "Dairy"},
        {"name": "Greek Yogurt", "category": "Dairy"},
        {"name": "Butter", "category": "Dairy"},
        {"name":"Ice Cream", "category": "Dairy"}
    ]
}

ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

@app.route('/')
def index():
    return render_template('index.html', current_time=datetime.utcnow())

@app.route('/user/<name>')
def user(name):
    if 'email' in session: #check if user is logged in
        role = user_roles.get(session['email'], 'shopper')
        return render_template('user_profile.html', name=name, email=session.get('email'), role=role)
    else:
        flash('Please login to view your profile.', 'danger')
        return redirect(url_for('login'))

@app.route('/about/')
def about():
    return render_template('about.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LogingPassForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        if email in users and users[email]['password'] == password:
            session['email'] = email
            flash('Login successful!', 'success')
            return redirect(url_for('user', name=users[email]['name']))
        elif email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['email'] = email
            flash('Admin Login successful!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/logout/')
def logout():
    session.pop('email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data
        users[email] = {'password': password, 'name': name}
        flash('You can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/ongoing/')
def ongoing():
    if 'email' not in session:
        flash('Please login to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('ongoing.html')

@app.route('/robochat/')
def depsek():
    return render_template('dsindex.html')

@app.route('/ask', methods=['POST'])
def ask_deepseek():
    try:
        user_query = request.json.get('query')
        if not user_query:
            return jsonify({"error": "Empty query"}), 400

        if not DEEPSEEK_API_KEY:
          return jsonify({"error": "DEEPSEEK_API_KEY is not set in environment variables"}), 500

        headers = {
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": user_query}]
        }

        response = requests.post(API_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()

        result = response.json()
        return jsonify({"answer": result['choices'][0]['message']['content']})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"API request failed: {str(e)}"}), 500
    except (KeyError, IndexError):
        return jsonify({"error": "Unexpected API response format"}), 500
    except Exception as e:
        return jsonify({"error":f"An unexpected error occured: {str(e)}"}),500

@app.route('/vendors/')
def vendor_list():
    if 'email' not in session:
        flash('Please login to view vendors.', 'danger')
        return redirect(url_for('login'))
    vendors_with_data = {}
    for vendor, products in vendors.items():
        vendors_with_data[vendor] = []
        for product in products:
            qty = random.randint(1, 500)
            measurement = random.choice(["Box", "Pieces", "Pounds", "Gallons", "Units"])
            vendors_with_data[vendor].append({
                "name": product["name"],
                "category": product["category"],
                "qty": qty,
                "measurement": measurement
            })
    return render_template('vendors.html', vendors=vendors_with_data)

@app.route('/admin/', methods=['GET', 'POST'])
def admin():
    if session.get('email') != ADMIN_EMAIL:
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))

    assign_form = AdminAssignRoleForm()
    assign_form.email.choices = [(email, email) for email in users.keys()]

    add_store_form = AdminAddStoreForm()

    if assign_form.validate_on_submit() and assign_form.submit.data:
        email = assign_form.email.data
        role = assign_form.role.data
        user_roles[email] = role
        flash(f'Role assigned to {email}.', 'success')
        return redirect(url_for('admin'))

    if add_store_form.validate_on_submit() and add_store_form.submit.data:
        store_name = add_store_form.store_name.data
        vendors[store_name] = [] #creates a new store
        flash(f'Store {store_name} added.', 'success')
        return redirect(url_for('admin'))
    return render_template('admin.html', assign_form=assign_form, add_store_form=add_store_form)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')