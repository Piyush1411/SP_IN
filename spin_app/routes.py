from flask import render_template, request, flash, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from spin_app import app, db
from spin_app.models import User, InfluencerProfile, SponsorProfile

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Please fill out all fields', category='danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        flash('Login successful', category='success')
        if user.role == 'sponsor':
            return redirect(url_for('sp_dash'))
        elif user.role == 'influencer':
            return redirect(url_for('inf_dash'))
        else:
            return redirect(url_for('login'))
    else:
        flash('Invalid username or password', category='danger')
        return redirect(url_for('login'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    email = request.form.get('email')
    name = request.form.get('fullName')
    password = request.form.get('password1')
    confirm_password = request.form.get('password2')
    role = request.form.get('role')

    if not username or not email or not name or not password or not confirm_password or not role:
        flash('Please fill out all fields', category='danger')
        return redirect(url_for('register'))
    
    if password != confirm_password:
        flash('Passwords do not match', category='danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already exists', category='danger')
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email already exists', category='danger')
        return redirect(url_for('register'))

    password_hash = generate_password_hash(password)
    new_user = User(username=username, email=email, password=password_hash, role=role)
    db.session.add(new_user)
    db.session.commit()

    if role == 'influencer':
        category = request.form.get('category')
        niche = request.form.get('niche')
        reach = request.form.get('reach')
        influencer_profile = InfluencerProfile(user_id=new_user.id, name=name, category=category, niche=niche, reach=reach)
        db.session.add(influencer_profile)
    elif role == 'sponsor':
        company_name = request.form.get('companyName')
        industry = request.form.get('industry')
        budget = request.form.get('budget')
        sponsor_profile = SponsorProfile(user_id=new_user.id, company_name=company_name, industry=industry, budget=budget)
        db.session.add(sponsor_profile)

    db.session.commit()

    flash('Registration successful', category='success')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been successfully logged out', category='primary')
    return render_template('home.html')

@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin_login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not username or not password:
        flash('Please fill out all fields', category='danger')
        return redirect(url_for('admin_login'))

    user = User.query.filter_by(username=username).first()

    if not user:
        flash('Username does not exist', category='danger')
        return redirect(url_for('admin_login'))

    if not check_password_hash(user.password, password):
        flash('Incorrect password', category='danger')
        return redirect(url_for('admin_login'))

    login_user(user)
    flash('Login successful', category='success')
    return redirect(url_for('admin_dash'))

@app.route('/admin_dash')
@login_required
def admin_dash():
    return render_template('admin_dash.html')

@app.route('/sp_dash')
@login_required
def sp_dash():
    return render_template('sp_dash.html')

@app.route('/inf_dash')
@login_required
def inf_dash():
    return render_template('inf_dash.html')
