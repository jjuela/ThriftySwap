from app import db
from flask_login import UserMixin
from datetime import datetime
import pytz

class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    inventories = db.relationship('Inventory', backref='store', lazy=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True) 
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(20), nullable=True)
    last_name = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    reset_code = db.Column(db.String(5))
    reset_expiration = db.Column(db.DateTime)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(64))
    profile_picture = db.Column(db.String(20), nullable=True, default='default.jpg')

class Inventory(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(50), nullable=False)
    material = db.Column(db.String(50), nullable=True)
    weight = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    value_per_item = db.Column(db.DECIMAL(10, 2), nullable=False)
    barcode = db.Column(db.String(50), nullable=True)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=True)
    type = db.Column(db.String(20))
    intake_transactions = db.relationship('IntakeTransaction', back_populates='inventory')
    outtake_transactions = db.relationship('OuttakeTransaction', back_populates='inventory')


class IntakeTransaction(db.Model):
    __tablename__ = 'intake_transaction'

    id = db.Column(db.Integer, primary_key=True)
    inventory_id = db.Column(db.Integer, db.ForeignKey('inventory.id'))
    item_name = db.Column(db.String(50))
    quantity = db.Column(db.Integer)
    user = db.Column(db.String)  # Assuming you have a user field
    timestamp = db.Column(db.DateTime)
    donor_info = db.Column(db.String)

    # Define the relationship with the Inventory model
    inventory = db.relationship('Inventory', back_populates='intake_transactions')

    @property
    def formatted_timestamp(self):
        # Assuming you want to format the timestamp in the same way as in the OuttakeTransaction class
        eastern_tz = pytz.timezone('America/New_York')
        return self.timestamp.astimezone(eastern_tz).strftime('%I:%M %p')



class OuttakeTransaction(db.Model):
    __tablename__ = 'outtake_transaction'
    id = db.Column(db.Integer, primary_key=True)
    inventory_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False)
    item_name = db.Column(db.String(50))  # Add this field to store the item name
    quantity = db.Column(db.Integer, nullable=False)
    donor_info = db.Column(db.String)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Define the relationship with the Inventory model
    inventory = db.relationship('Inventory', back_populates='outtake_transactions')

    @property
    def timestamp_eastern(self):
    # Convert timestamp to Eastern Time (ET)
        eastern_tz = pytz.timezone('America/New_York')
        return self.timestamp.astimezone(eastern_tz)

    @property
    def formatted_timestamp(self):
        # Format the timestamp to show hours (12-hour clock), minutes, and AM/PM
        return self.timestamp_eastern.strftime('%I:%M %p')
