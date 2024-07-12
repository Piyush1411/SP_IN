# app.py
from spin_app import app
from flask import render_template
from sqlalchemy.exc import SQLAlchemyError
from spin_app import db

if __name__ == '__main__':
    app.run(debug=True)

 

