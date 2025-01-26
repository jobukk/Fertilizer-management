from . import db
from sqlalchemy.sql import func
from sqlalchemy_serializer import SerializerMixin


class Farmer(db.Model, SerializerMixin):
    __tablename__ = "farmers"
    serialize_rules = ('-orders.farmer',)
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    phoneNumber = db.Column(db.Integer, nullable=False)
    county = db.Column(db.String(100), nullable=False)
    subCounty = db.Column(db.String(100), nullable=False)
    farmSize = db.Column(db.String(150), nullable=False)
    cropType = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    orders = db.relationship('Order', backref='farmer', lazy='dynamic')
    #representation
    def __repr__(self):
        return f'<User {self.firstName} {self.id}'


