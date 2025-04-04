
from flask import Flask, render_template, session, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_moment import Moment
from datetime import datetime
from wtforms import  PasswordField, BooleanField
from flask_moment import Moment
from datetime import datetime
from dotenv import load_dotenv
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'
bootstrap = Bootstrap(app)

moment = Moment(app)

class NameForm(FlaskForm):
    name = StringField('What is your name???', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LogingPassForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
    Email()])
    password = PasswordField('Password', validators=[
    DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    name = StringField('Investor Name:', validators=[DataRequired(), Length(1,64), Regexp('^[A-Za-z][A-Za-z]* ', 0,
                                                                                         'Usernames must have only letters')])
    username = StringField('User ID: ', validators=[DataRequired(), Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
'Usernames must have only letters, numbers, dots or '
    'underscores')])
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
    Email()])
    password = PasswordField('Password', validators=[
    DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

@app.route('/')
def index():
    return render_template('index.html',
                            current_time=datetime.utcnow())

@app.route('/user/<name>')
def user(name):
    name="This is the name:  "+name
    return render_template('user.html', name=name)

@app.route('/about/')
def about():
    return render_template('about.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LogingPassForm()
    if form.validate_on_submit():
        old_email = session.get('email')
        if old_email is not None and old_email != form.email.data:
            flash('Looks like you new investor please register using your email!')
        session['email'] = form.email.data
        return redirect(url_for('login'))
    flash('Welcome!')
    return render_template('login.html',form = form, name = session.get('name'))

@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        flash('You can now login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/robochat/')
def depsek():
    return render_template('dsindex.html')

@app.route('/ask', methods=['POST'])
def ask_deepseek():
    try:
        user_query = request.json.get('query')
        if not user_query:
            return jsonify({"error": "Empty query"}), 400

        headers = {
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "deepseek-chat",  # Confirm correct model name
            "messages": [{"role": "user", "content": user_query}]
        }

        response = requests.post(API_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()  # Raise HTTP errors

        result = response.json()
        return jsonify({"answer": result['choices'][0]['message']['content']})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"API request failed: {str(e)}"}), 500
    except KeyError:
        return jsonify({"error": "Unexpected API response format"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')



