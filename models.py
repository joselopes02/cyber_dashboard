# models.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class URL(db.Model):
    __tablename__ = 'urls'
    url = db.Column(db.Text, primary_key=True)  
    malicious_flags = db.Column(db.Integer)
    threat_names = db.Column(db.Text)
    shasum = db.Column(db.Text, index=True)      
    type = db.Column(db.Text)
    times_submitted = db.Column(db.Integer)
    reputation = db.Column(db.Integer)    

class Download(db.Model):
    __tablename__ = 'downloads'
    md5 = db.Column(db.Text, primary_key=True)     
    file_data = db.Column(db.LargeBinary)
    malicious_flags = db.Column(db.Integer)
    popular_label = db.Column(db.Text)
    sha256 = db.Column(db.Text, index=True)        
    type = db.Column(db.Text)
    file_size = db.Column(db.Integer)
    times_submitted = db.Column(db.Integer)
    reputation = db.Column(db.Integer)

class Attack(db.Model):
    __tablename__ = 'attacks'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Text, index=True)           
    source_ip = db.Column(db.Text)
    source_port = db.Column(db.Integer)
    honeypot_name = db.Column(db.Text)
    honeypot_ip = db.Column(db.Text)
    protocol = db.Column(db.Text)
    honeypot_service = db.Column(db.Text)
    md5 = db.Column(db.Text, index=True)            
    url = db.Column(db.Text, index=True)            
    city = db.Column(db.Text)
    country_name = db.Column(db.Text)
    continent = db.Column(db.Text)
    org = db.Column(db.Text)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class Augmented_Attacks(db.Model):
    __tablename__ = 'augmented_attacks'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Text, index=True)           
    source_ip = db.Column(db.Text)
    source_port = db.Column(db.Integer)
    honeypot_name = db.Column(db.Text)
    honeypot_ip = db.Column(db.Text)
    protocol = db.Column(db.Text)
    honeypot_service = db.Column(db.Text)
    md5 = db.Column(db.Text, index=True)            
    url = db.Column(db.Text, index=True)            
    city = db.Column(db.Text)
    country_name = db.Column(db.Text)
    continent = db.Column(db.Text)
    org = db.Column(db.Text)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
