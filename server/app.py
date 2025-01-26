from . import app, db, swagger
from flask import Flask, request, make_response, jsonify
from .models import Farmer, NCPBStaff, Fertilizer, Inventory, Depot, Transaction, Order, Payment, Supplier 
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from functools import wraps
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token


CORS(app)
import secrets

# Generate a random 32-byte secret key
secret_key = secrets.token_hex(32)
app.config["JWT_SECRET_KEY"] = secret_key  # Replace with a strong secret key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=3)
jwt = JWTManager(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'eventgoticketing@gmail.com'
app.config['MAIL_PASSWORD'] = 'rukjdikodbwpgisx'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail=Mail(app)

@app.route('/')
def hello():
    """
    hello route
    """
    return "Hello, World! This is the fertilizer management app"

@app.route("/signup/farmer", methods=["POST"])
def farmer_signup():
    data = request.json
    firstName = data.get("firstName")
    lastName = data.get("lastName")
    password = data.get("password")
    phoneNumber = data.get("phoneNumber")
    county = data.get("county")
    subCounty = data.get("subCounty")
    farmSize = data.get("farmSize")
    cropType = data.get("cropType")
    email = data.get("email")

    if firstName and lastName and email and password:
        farmer = Farmer.query.filter_by(email=email).first()
        if farmer:
            return make_response({"message": "Please Sign In"}, 200)
        
        farmer = Farmer(
            email=email,
            password=generate_password_hash(password),
            firstName=firstName,
            lastName=lastName,
            phoneNumber=phoneNumber,
            county=county,
            subCounty=subCounty,
            farmSize=farmSize,
            cropType=cropType
        )
        db.session.add(farmer)
        db.session.commit()
        # Generate a JWT token
        token = create_access_token(identity={"id": farmer.id, "role": "farmer"})
        return jsonify({
            "message": "Farmer created successfully!",
            "token": token,
            "role": "farmer",
            "id": farmer.id,
            "email": farmer.email
        }), 201

        return make_response({"message": "Farmer created"}, 201)
    
    return make_response({"message": "Unable to create farmer account"}, 500)

@app.route("/login/farmer", methods=["POST"])
def farmer_login():
    auth = request.json
    if not auth or not auth.get("email") or not auth.get("password"):
        return make_response("Proper credentials were not provided", 401)
    
    farmer = Farmer.query.filter_by(email=auth.get("email")).first()
    if not farmer:
        return make_response("Please create an account", 401)
    if check_password_hash(farmer.password, auth.get("password")):
        token = create_access_token(identity={"id": farmer.id, "role": "farmer"}, fresh=True)
        print(f"Encoded Token: {token}") #Debug token
        return jsonify({"token": token, "role": "farmer", "id": farmer.id,"email": farmer.email}), 201    
        
    return make_response("Please check your credentials", 401)


if __name__ == "__main__":
    app.run(port=5000, debug=True)