from flask import render_template, request, flash, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from spin_app import app, db
from spin_app.models import User, InfluencerProfile, SponsorProfile, Campaign
from datetime import datetime

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
    if current_user.role != 'sponsor':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))

    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()
    campaigns = Campaign.query.filter_by(owner_id=sponsor_profile.id).all()
    return render_template('sp_dash.html', campaigns=campaigns)


@app.route('/inf_dash')
@login_required
def inf_dash():
    return render_template('inf_dash.html')

@app.route('/campaigns')
@login_required
def campaigns():
    if current_user.role != 'sponsor':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))

    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()
    campaigns = Campaign.query.filter_by(owner_id=sponsor_profile.id).all()
    return render_template('sp_dash.html', campaigns=campaigns)

@app.route('/campaigns/new', methods=['GET'])
@login_required
def new_campaign():
    if current_user.role != 'sponsor':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))

    return render_template('new_campaign.html')

@app.route('/campaigns/new', methods=['POST'])
@login_required
def new_campaign_post():
    if current_user.role != 'sponsor':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))

    name = request.form.get('name')
    description = request.form.get('description')
    start_date_str = request.form.get('start_date')
    end_date_str = request.form.get('end_date')
    budget = request.form.get('budget')
    visibility = request.form.get('visibility')
    goals = request.form.get('goals')

    # Convert date strings to date objects
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid date format', category='danger')
        return redirect(url_for('new_campaign'))

    if not name or not description or not start_date or not end_date or not budget or not visibility or not goals:
        flash('Please fill out all fields', category='danger')
        return redirect(url_for('new_campaign'))

    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    new_campaign = Campaign(
        name=name,
        description=description,
        start_date=start_date,
        end_date=end_date,
        budget=budget,
        visibility=visibility,
        goals=goals,
        owner_id=sponsor_profile.id
    )

    db.session.add(new_campaign)
    db.session.commit()

    flash('Campaign created successfully', category='success')
    return render_template('sp_dash.html')  # Redirect to sp_dash instead of campaigns

@app.route("/campaigns/<int:id>/", methods=['GET'])
@login_required
def view_campaign(id):
    camp = Campaign.query.get(id)
    if not camp:
        flash('Campaign does not exist')
        return redirect(url_for('sp_dash'))
    return render_template('view_campaign.html', campaign=camp)

@app.route('/campaigns/<int:id>/edit', methods=['GET'])
@login_required
def edit_campaign(id):
    campaign = Campaign.query.get(id)
    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    if campaign.owner_id != sponsor_profile.id:
        flash('You do not have permission to edit this campaign', category='danger')
        return redirect(url_for('campaigns'))

    return render_template('edit_campaign.html', campaign=campaign)

@app.route('/campaigns/<int:id>/edit', methods=['POST'])
@login_required
def edit_campaign_post(id):
    campaign = Campaign.query.get(id)
    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    if campaign.owner_id != sponsor_profile.id:
        flash('You do not have permission to edit this campaign', category='danger')
        return redirect(url_for('campaigns'))

    name = request.form.get('name')
    description = request.form.get('description')
    start_date_str = request.form.get('start_date')
    end_date_str = request.form.get('end_date')
    budget = request.form.get('budget')
    visibility = request.form.get('visibility')
    goals = request.form.get('goals')

    # Convert date strings to date objects
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid date format', category='danger')
        return redirect(url_for('edit_campaign', id=campaign.id))

    if not name or not description or not start_date or not end_date or not budget or not visibility or not goals:
        flash('Please fill out all fields', category='danger')
        return redirect(url_for('edit_campaign', id=campaign.id))

    campaign.name = name
    campaign.description = description
    campaign.start_date = start_date
    campaign.end_date = end_date
    campaign.budget = budget
    campaign.visibility = visibility
    campaign.goals = goals

    db.session.commit()
    flash('Campaign updated successfully', category='success')
    return redirect(url_for('sp_dash'))

@app.route('/campaign/<int:id>/delete')
@login_required
def delete_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('campaign does not exist', category='danger')
        return redirect(url_for('sp_dash'))
    return render_template('delete_campaign.html', campaign=campaign)

@app.route('/campaign/<int:id>/delete', methods=['POST'])
@login_required
def delete_campaign_post(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('campaign does not exist', category='danger')
        return redirect(url_for('sp_dash'))
    db.session.delete(campaign)
    db.session.commit()

    flash('Campaign deleted successfully', category='success')
    return redirect(url_for('sp_dash'))