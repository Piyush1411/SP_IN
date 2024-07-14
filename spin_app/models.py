#models.py
from spin_app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False) 
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    influencer_profile = db.relationship('InfluencerProfile', backref='user', lazy=True, cascade='all, delete-orphan')
    sponsor_profile = db.relationship('SponsorProfile', backref='user', lazy=True, cascade='all, delete-orphan')

class InfluencerProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(120), nullable=False)
    niche = db.Column(db.String(120), nullable=False)
    reach = db.Column(db.Integer, nullable=False)

class SponsorProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(120), nullable=False)
    industry = db.Column(db.String(120), nullable=False)
    budget = db.Column(db.Float, nullable=False)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    visibility = db.Column(db.String(20), nullable=False)  # 'public' or 'private'
    goals = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('sponsor_profile.id'), nullable=False)
    owner = db.relationship('SponsorProfile', backref=db.backref('campaigns', lazy=True, cascade='all, delete-orphan'))

class AdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor_profile.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer_profile.id'), nullable=False)
    messages = db.Column(db.Text, nullable=True)
    requirements = db.Column(db.Text, nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    negotiated_payment_amount = db.Column(db.Float)
    status = db.Column(db.String(20), nullable=False)  # 'Pending', 'Accepted', 'Rejected'
    campaign = db.relationship('Campaign', backref=db.backref('ad_requests', lazy=True, cascade='all, delete-orphan'))
    sponsor = db.relationship('SponsorProfile', backref=db.backref('ad_requests', lazy=True, cascade='all, delete-orphan'))  
    influencer = db.relationship('InfluencerProfile', backref=db.backref('ad_requests', lazy=True, cascade='all, delete-orphan'))
