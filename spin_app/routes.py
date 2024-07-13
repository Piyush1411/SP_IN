from flask import render_template, request, flash, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from spin_app import app, db
from spin_app.models import User, InfluencerProfile, SponsorProfile, Campaign, AdRequest
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
    if current_user.role != 'admin':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))
    
    # Query for statistics
    num_users = User.query.count()
    num_campaigns_public = Campaign.query.filter_by(visibility='public').count()
    num_campaigns_private = Campaign.query.filter_by(visibility='private').count()
    num_ad_requests = AdRequest.query.count()

    return render_template('admin_dash.html', 
                           num_users=num_users,
                           num_campaigns_public=num_campaigns_public,
                           num_campaigns_private=num_campaigns_private,
                           num_ad_requests=num_ad_requests)

@app.route('/sp_dash')
@login_required
def sp_dash():
    if current_user.role != 'sponsor':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))

    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()
    campaigns = Campaign.query.filter_by(owner_id=sponsor_profile.id).all()
    
    return render_template('sp_dash.html',sponsor_profile=sponsor_profile, campaigns=campaigns, search_result=None)

@app.route('/sp_dash', methods=['POST'])
@login_required
def sp_dash_post():
    if current_user.role != 'sponsor':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))

    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()
    
    searchbyniche = request.form.get('searchbyniche')
    searchbyreach = request.form.get('searchbyreach')
    influencer_id = request.form.get('influencer')

    # Perform search based on input criteria
    query = InfluencerProfile.query

    if searchbyniche:
        query = query.filter(InfluencerProfile.niche.ilike(f"%{searchbyniche}%"))

    if searchbyreach:
        query = query.filter(InfluencerProfile.reach >= int(searchbyreach))

    if influencer_id:
        query = query.filter_by(id=influencer_id)

    search_result = query.all()

    return render_template('sp_dash.html', sponsor_profile=sponsor_profile, search_result=search_result)

@app.route('/inf_dash', methods=['GET'])
@login_required
def inf_dash():
    if current_user.role != 'influencer':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))
    
    influencer_profile = InfluencerProfile.query.filter_by(user_id=current_user.id).first()
    return render_template('inf_dash.html', influencer_profile=influencer_profile, search_result=None)


@app.route('/inf_dash', methods=['POST'])
@login_required
def inf_dash_post():
    if current_user.role != 'influencer':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))
    
    # Fetch influencer profile
    influencer_profile = InfluencerProfile.query.filter_by(user_id=current_user.id).first()
    
    # Get search criteria from form
    searchbyniche = request.form.get('searchbyniche')
    searchbyreach = request.form.get('searchbyreach')
    sponsor_id = request.form.get('sponsor')

    # Perform search based on input criteria
    query = Campaign.query.filter_by(visibility='public')

    if searchbyniche:
        query = query.filter(Campaign.goals.ilike(f"%{searchbyniche}%"))

    if searchbyreach:
        query = query.filter(Campaign.owner.has(InfluencerProfile.reach >= searchbyreach))

    search_result = query.all()

    return render_template('inf_dash.html', influencer_profile=influencer_profile, search_result=search_result)


@app.route('/clear_search', methods=['POST'])
@login_required
def clear_search():
    if current_user.role == 'sponsor':
        return redirect(url_for('sp_dash'))
    elif current_user.role == 'influencer':
        return redirect(url_for('inf_dash'))
    else:
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))

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
    return render_template('sp_dash.html') 

@app.route('/campaign/<int:id>')
@login_required
def view_campaign(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('Campaign not found.', category='danger')
        return redirect(url_for('sp_dash'))
    
    # Fetch the ad request related to this campaign, if applicable
    ad_request = AdRequest.query.filter_by(campaign_id=id).first()

    return render_template('view_campaign.html', campaign=campaign, ad_request=ad_request)

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
    return redirect(url_for('view_campaign', id=campaign.id))

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
    return redirect(url_for('view_campaign', id=campaign.id))

@app.route('/ad_request/create', methods=['GET'])
@login_required
def create_ad_request():
    campaign_id = request.args.get('campaign_id')
    campaign = Campaign.query.get(campaign_id)
    
    # Fetch sponsor profile associated with the current user
    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    if not sponsor_profile:
        flash('You do not have a sponsor profile', 'danger')
        return redirect(url_for('sp_dash'))  # Adjust redirection as per your application flow

    # Fetch all sponsors associated with the sponsor profile
    sponsors = [sponsor_profile]  # Assuming sponsor_profile itself is the sponsor
    
    # Fetch all influencers
    influencers = InfluencerProfile.query.all()

    return render_template('new_ad_request.html', campaign=campaign, sponsors=sponsors, influencers=influencers)

@app.route('/ad_request/create', methods=['POST'])
@login_required
def create_ad_request_post():
    campaign_id = request.form.get('campaign_id')
    sponsor_id = request.form.get('sponsor_id')
    influencer_id = request.form.get('influencer_id')
    messages = request.form.get('messages')
    requirements = request.form.get('requirements')
    payment_amount = request.form.get('payment_amount')
    status = request.form.get('status')

    # Validate form data
    if not (campaign_id and sponsor_id and influencer_id and requirements and payment_amount and status):
        flash('Please fill out all required fields', 'danger')
        return redirect(url_for('create_ad_request', campaign_id=campaign_id))

    # Create a new ad request
    ad_request = AdRequest(
        campaign_id=campaign_id,
        sponsor_id=sponsor_id,
        influencer_id=influencer_id,
        messages=messages,
        requirements=requirements,
        payment_amount=payment_amount,
        status=status
    )

    db.session.add(ad_request)
    db.session.commit()

    flash('Ad request created successfully', 'success')
    return redirect(url_for('view_campaign', id=campaign_id))

@app.route('/ad_request/<int:id>')
@login_required
def view_ad_request(id):
    ad_request = AdRequest.query.get(id)
    if not ad_request:
        flash('Ad Request not found.', category='danger')
        return redirect(url_for('sp_dash'))

    # Assuming campaign is related to the ad request, fetch it here
    campaign = ad_request.campaign

    return render_template('view_ad_request.html', ad_request=ad_request, campaign=campaign)

@app.route('/ad_request/<int:id>/edit', methods=['GET'])
@login_required
def edit_ad_request(id):
    ad_request = AdRequest.query.get(id)
    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    if not ad_request:
        flash('Ad Request does not exist', category='danger')
        return redirect(url_for('sp_dash'))

    if ad_request.sponsor_id != sponsor_profile.id:
        flash('You do not have permission to edit this ad request', category='danger')
        return redirect(url_for('sp_dash'))

    return render_template('edit_ad_request.html', ad_request=ad_request)

@app.route('/ad_request/<int:id>/edit', methods=['POST'])
@login_required
def edit_ad_request_post(id):
    ad_request = AdRequest.query.get(id)
    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    if not ad_request:
        flash('Ad Request does not exist', category='danger')
        return redirect(url_for('sp_dash'))

    if ad_request.sponsor_id != sponsor_profile.id:
        flash('You do not have permission to edit this ad request', category='danger')
        return redirect(url_for('sp_dash'))

    influencer_id = request.form.get('influencer_id')
    messages = request.form.get('messages')
    requirements = request.form.get('requirements')
    payment_amount = request.form.get('payment_amount')
    status = request.form.get('status')

    try:
        payment_amount = float(payment_amount)
    except ValueError:
        flash('Invalid payment amount', category='danger')
        return redirect(url_for('edit_ad_request', id=ad_request.id))

    if not influencer_id or not messages or not requirements or not payment_amount or not status:
        flash('Please fill out all fields', category='danger')
        return redirect(url_for('edit_ad_request', id=ad_request.id))

    ad_request.influencer_id = influencer_id
    ad_request.messages = messages
    ad_request.requirements = requirements
    ad_request.payment_amount = payment_amount
    ad_request.status = status

    db.session.commit()
    flash('Ad Request updated successfully', category='success')
    return redirect(url_for('view_ad_request', id=ad_request.id))

@app.route('/ad_request/<int:id>/delete', methods=['GET'])
@login_required
def delete_ad_request(id):
    ad_request = AdRequest.query.get(id)
    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    if not ad_request:
        flash('Ad Request does not exist', category='danger')
        return redirect(url_for('sp_dash'))

    if ad_request.sponsor_id != sponsor_profile.id:
        flash('You do not have permission to delete this ad request', category='danger')
        return redirect(url_for('sp_dash'))

    # Assuming you want to confirm deletion before proceeding
    return render_template('delete_ad_request.html', ad_request=ad_request)

@app.route('/ad_request/<int:id>/delete', methods=['POST'])
@login_required
def delete_ad_request_post(id):
    ad_request = AdRequest.query.get(id)
    sponsor_profile = SponsorProfile.query.filter_by(user_id=current_user.id).first()

    if not ad_request:
        flash('Ad Request does not exist', category='danger')
        return redirect(url_for('sp_dash'))

    if ad_request.sponsor_id != sponsor_profile.id:
        flash('You do not have permission to delete this ad request', category='danger')
        return redirect(url_for('sp_dash'))

    db.session.delete(ad_request)
    db.session.commit()

    flash('Ad Request deleted successfully', category='success')
    return redirect(url_for('sp_dash'))


@app.before_request
def before_request():
    g.user = current_user


@app.route('/show_ad_requests', methods=['GET'])
@login_required
def show_ad_requests():
    if current_user.role != 'influencer':
        flash('You do not have permission to access this page', category='danger')
        return redirect(url_for('home'))
    
    influencer_profile = InfluencerProfile.query.filter_by(user_id=current_user.id).first()
    ad_requests = AdRequest.query.filter_by(influencer_id=influencer_profile.id).all()

    return render_template('show_ad_requests.html', influencer_profile=influencer_profile, ad_requests=ad_requests)






