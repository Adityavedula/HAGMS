from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from db import db  # This assumes your db is initialized in db.py
from models import User, WorkoutPlan, Exercise, NutritionLog, Progress  # Your model definitions

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fitness_app.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='sha256')
        name = request.form['name']
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        new_user = User(email=email, password=password, name=name)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful, please log in')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/workout_plans')
@login_required
def workout_plans():
    plans = WorkoutPlan.query.filter_by(created_by=current_user.id).all()
    return render_template('workout_plans.html', plans=plans)

@app.route('/workout_plans/<int:id>')
@login_required
def workout_plan(id):
    plan = WorkoutPlan.query.get_or_404(id)
    return render_template('workout_plan.html', plan=plan)

@app.route('/nutrition_logs')
@login_required
def nutrition_logs():
    logs = NutritionLog.query.filter_by(user_id=current_user.id).all()
    return render_template('nutrition_logs.html', logs=logs)

@app.route('/progress_logs')
@login_required
def progress_logs():
    logs = Progress.query.filter_by(user_id=current_user.id).all()
    return render_template('progress_logs.html', logs=logs)

@app.route('/add_nutrition_log', methods=['GET', 'POST'])
@login_required
def add_nutrition_log():
    if request.method == 'POST':
        new_log = NutritionLog(
            user_id=current_user.id,
            date=datetime.strptime(request.form['date'], '%Y-%m-%d'),
            meal=request.form['meal'],
            calories=float(request.form['calories']),
            protein=float(request.form['protein']),
            carbs=float(request.form['carbs']),
            fats=float(request.form['fats'])
        )
        db.session.add(new_log)
        db.session.commit()
        return redirect(url_for('nutrition_logs'))
    return render_template('add_nutrition_log.html')

@app.route('/add_progress_log', methods=['GET', 'POST'])
@login_required
def add_progress_log():
    if request.method == 'POST':
        new_log = Progress(
            user_id=current_user.id,
            date=datetime.strptime(request.form['date'], '%Y-%m-%d'),
            weight=float(request.form['weight']),
            body_fat_percentage=float(request.form['body_fat_percentage']),
            notes=request.form['notes']
        )
        db.session.add(new_log)
        db.session.commit()
        return redirect(url_for('progress_logs'))
    return render_template('add_progress_log.html')

if __name__ == '__main__':
    app.run(debug=True)
