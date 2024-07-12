from dotenv import load_dotenv
import os
from spin_app import app


app.config['SECRET_KEY'] = '12312421'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


