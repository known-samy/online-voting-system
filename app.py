from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from waitress import serve  # Importing Waitress

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    votes = db.Column(db.Integer, default=0)

# Routes
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Registration Successful!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard')) if user.is_admin else redirect(url_for('vote'))
        else:
            flash('Invalid credentials!')
    return render_template('login.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        candidate = Candidate(name=name)
        db.session.add(candidate)
        db.session.commit()
        flash('Candidate Added!')
    candidates = Candidate.query.all()
    return render_template('admin.html', candidates=candidates)

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    if current_user.has_voted:
        flash('You have already voted!')
        return redirect(url_for('result'))
    candidates = Candidate.query.all()
    if request.method == 'POST':
        candidate_id = request.form['candidate']
        candidate = Candidate.query.get(candidate_id)
        candidate.votes += 1
        current_user.has_voted = True
        db.session.commit()
        flash('Vote cast successfully!')
        return redirect(url_for('result'))
    return render_template('vote.html', candidates=candidates)

@app.route('/result')
@login_required
def result():
    candidates = Candidate.query.order_by(Candidate.votes.desc()).all()
    return render_template('result.html', candidates=candidates)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Main entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database tables are created within the app context
    serve(app, host='0.0.0.0', port=5000)  # Use Waitress to serve the app


