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

@app.route("/signup/staff", methods=["POST"])
def staff_signup():
    data = request.json
    firstName = data.get("firstName")
    lastName = data.get("lastName")
    password = data.get("password")
    phoneNumber = data.get("phoneNumber")
    role = data.get("role")
    center = data.get("center")
    department = data.get("department")
    email = data.get("email")

    if firstName and lastName and email and password:
        staff = NCPBStaff.query.filter_by(email=email).first()
        if staff:
            return make_response({"message": "Please Sign In"}, 200)
        
        staff = NCPBStaff(
            email=email,
            password=generate_password_hash(password),
            firstName=firstName,
            lastName=lastName,
            phoneNumber=phoneNumber,
            role=role,
            center=center,
            department=department
        )
        db.session.add(staff)
        db.session.commit()

        # Generate a JWT token with the staff's role
        token = create_access_token(identity={"id": staff.id, "role": role})
        return jsonify({
            "message": "Staff created successfully!",
            "token": token,
            "role": role
        }), 201
    
    return make_response({"message": "Unable to create staff account"}, 500)

@app.route("/login/staff", methods=["POST"])
def staff_login():
    auth = request.json
    if not auth or not auth.get("email") or not auth.get("password"):
        return make_response("Proper credentials were not provided", 401)
    
    staff = NCPBStaff.query.filter_by(email=auth.get("email")).first()
    if not staff:
        return make_response("Please create an account", 401)
    
    if check_password_hash(staff.password, auth.get("password")):
        token = create_access_token(identity={"id": staff.id, "role": staff.role}, fresh=True)
        print(f"Encoded Token: {token}")
        return jsonify({"token": token, "role": staff.role}), 201
    
    return make_response("Please check your credentials", 401)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers["Authorization"]
            print(f"Received Token: {token}")  # Debug print

            # Remove "Bearer " if present
            if token.startswith("Bearer "):
                token = token[len("Bearer "):]
                print(f"Token after removing 'Bearer ': {token}")  # Debug print
        
        if not token:
            return make_response({"message": "Token is missing"}, 401)
        
        try:
            data = jwt.decode(token, "secrets", algorithms=["HS256"])
            current_user = NCPBStaff.query.filter_by(id=data["id"]).first() or Farmer.query.filter_by(id=data["id"]).first()
            print(current_user)
            # if not current_user:
            #     current_user = NCPBStaff.query.filter_by(id=data["id"]).first()
            
            if not current_user:
                return make_response({"message": "User not found"}, 401)
            
            # Explicit role assignment
            if isinstance(current_user, NCPBStaff):
                current_user.role = "admin"
            elif isinstance(current_user, Farmer):
                current_user.role = "farmer"
            print(f"Current User: {current_user.email}, Role: {current_user.role}")  # Debug print
        except jwt.ExpiredSignatureError:
            return make_response({"message": "Token has expired"}, 401)
        except jwt.InvalidTokenError as e:
            return make_response({"message": f"Token is invalid: {str(e)}"}, 401)
        except Exception as e:
            return make_response({"message": f"An error occurred: {str(e)}"}, 500)
        
        return f(current_user, *args, **kwargs)
    
    return decorated

#fertilizer routes
@app.route('/fertilizer', methods=['GET', 'POST'])
# @token_required
# def manageFertilizer(current_user):
def manageFertilizer():
    if request.method == 'GET':
        fertilizers = []
        for fertilizer in Fertilizer.query.all():
            fertilizer_dict = fertilizer.to_dict()
            fertilizers.append(fertilizer_dict)

        return make_response(jsonify(fertilizers), 200)
    
    elif request.method == 'POST':
        # if current_user.role != 'admin':
        #     return make_response({"message": "Admin access required"}, 403)
        
        data = request.json
        if not data:
            return make_response({"message": "Invalid JSON"}, 400)
        
        # Check required fields
        required_fields = ["name", "Type", "NutrientComposition", "Manufacturer", "ApplicationMethod", "ApplicationRate", "PackagingSize", "Price", "ExpirationDate", "SafetyInformation", "UsageInstructions", "StorageConditions", "EnvironmentalImpact"]
        for field in required_fields:
            if field not in data:
                return make_response({"message": f"Missing field: {field}"}, 400)
        
        new_fertilizer = Fertilizer(
            name=data.get("name"),
            Type=data.get("Type"),
            NutrientComposition=data.get("NutrientComposition"),
            Manufacturer=data.get("Manufacturer"),
            ApplicationMethod=data.get("ApplicationMethod"),
            ApplicationRate=data.get("ApplicationRate"),
            PackagingSize=data.get("PackagingSize"),
            Price=data.get("Price"),
            ExpirationDate=data.get("ExpirationDate"),
            SafetyInformation=data.get("SafetyInformation"),
            UsageInstructions=data.get("UsageInstructions"),
            StorageConditions=data.get("StorageConditions"),
            EnvironmentalImpact=data.get("EnvironmentalImpact"),
        )
        db.session.add(new_fertilizer)
        db.session.commit()

        fertilizer_dict = new_fertilizer.to_dict()

        return make_response(jsonify(fertilizer_dict), 201)

@app.route('/fertilizer/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
def fertilizer_by_id(id):
    fertilizer = Fertilizer.query.filter_by(id=id).first()
    if not fertilizer:
        # Return a 404 error if the fertilizer is not found
        return make_response(
            jsonify({"error": f"Fertilizer with id {id} not found"}), 
            404
        )
    if request.method == 'GET':
        fertilizer_dict = fertilizer.to_dict()

        response = make_response(
            jsonify(fertilizer_dict),
            200
        )

        return response

    elif request.method == 'DELETE':
        if not fertilizer:
            return make_response(jsonify({
            "message": "data already deleted"
        }), 200)
        db.session.delete(fertilizer)
        db.session.commit()

        repsonse_body = {
            "delete_successful": True,
            "message": "Fertilizer deleted"
        }

        response = make_response(
            jsonify(repsonse_body),
            200
        )
        return response

    elif request.method == 'PATCH':
        fertilizer = Fertilizer.query.filter_by(id=id).first()

        if not fertilizer:
            return make_response({"message": "Fertilizer with id {id} not found"}, 404)

        data = request.form or request.json
        if not data:
            return make_response({"message": "No data provided to update"}, 400)

        for attr in data:
            if hasattr(fertilizer, attr):
                setattr(fertilizer, attr, data.get(attr))

        # print("Before patching")
        # print(fertilizer)

        db.session.commit()

        fertilizer_dict = fertilizer.to_dict()
        # print("After patching")
        # print(fertilizer_dict)

        response = make_response(
            jsonify(fertilizer_dict),
            200
        )


        return response

#inventory routes
@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    if request.method == 'GET':
        inventories = []
        for inventory in Inventory.query.all():
            inventory_dict = inventory.to_dict()
            inventories.append(inventory_dict)
        return make_response(jsonify(inventories), 200)

    elif request.method == 'POST':
        data = request.json
        if not data:
            return make_response({"message": "Invalid JSON"}, 400)

    #check required fields
    required_fields = ["stockQuantity","lastRestockedDate","depots_id","fertilizers_id"]
    for field in required_fields:
            if field not in data:
                return make_response({"message": f"Missing field: {field}"}, 400)

    new_inventory = Inventory(
        stockQuantity = data.get("stockQuantity"),
        lastRestockedDate=data.get("lastRestockedDate"),
        depots_id=data.get("depots_id"),
        fertilizers_id=data.get("fertilizers_id")
    )
    db.session.add(new_inventory)
    db.session.commit()
    inventory_dict = new_inventory.to_dict()
    return make_response(jsonify(inventory_dict), 201)

@app.route('/inventory/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
def invetory_by_id(id):
    inventory = Inventory.query.filter_by(id=id).first()
    if not inventory:
        return make_response({"message": f"Inventory with id {id} not found"}, 404)
    if request.method == 'GET':
        inventory_dict = inventory.to_dict()
        return make_response(jsonify(inventory_dict), 200)

    elif request.method == 'DELETE':
        if not inventory:
            return make_response(jsonify({
            "message": "data already deleted"
        }), 200)
        db.session.delete(inventory)
        db.session.commit()
        response_body = {"message": "Item deleted successfully"}
        return jsonify(response_body), 200

    elif request.method == "PATCH":
        inventory = Inventory.query.filter_by(id=id).first()
        if not inventory:
            return make_response({"message": "Inventory not found"})
        data = request.form or request.json
        if not data:
           return make_response({"message": "No data provided to update"}, 400)

        for attr in data:
            if hasattr(inventory, attr):
                setattr(inventory, attr, data.get(attr))

        
        db.session.commit()
        inventory_dict = inventory.to_dict()
        return make_response(jsonify(inventory_dict), 200)

#depot routes
@app.route('/depot', methods=['GET','POST'])
def depot():
    if request.method == 'GET':
        depots = []
        for depot in Depot.query.all():
            depot_dict = depot.to_dict()
            depots.append(depot_dict)
        return make_response(jsonify(depots), 200)
    elif request.method == 'POST':
        data = request.json
        if not data:
            return make_response({"message": "Invalid JSON"}, 400)

        #check required fields
        required_fields = ["depotName","location","phoneNumber","email","managerName","storageCapacity"]       
        if not data:
            return make_response({"message": "Invalid JSON"}, 400)

        new_depot = Depot(
            depotName=data.get("depotName"),
            location=data.get("location"),
            phoneNumber=data.get("phoneNumber"),
            email=data.get("email"),
            managerName=data.get("managerName"),
            storageCapacity=data.get("storageCapacity")
        )
        db.session.add(new_depot)
        db.session.commit()
        depot_dict = new_depot.to_dict()
        
        return make_response(jsonify(depot_dict), 201)

@app.route('/depot/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
def depot_by_id(id):
    depot = Depot.query.filter_by(id=id).first()
    if not depot:
        return make_response({"message": "Depot with id {id} not found"}, 404)
    if request.method == 'GET':
        depot_dict = depot.to_dict()
        return make_response(jsonify(depot_dict), 200)

    elif request.method == 'DELETE':
        if not depot:
            return make_response(jsonify({
            "message": "data already deleted"
        }), 200)
        db.session.delete(depot)
        db.session.commit()
        
        return make_response(jsonify(
            {
            "delete_successful": True,
            "message": "depot deleted"
        }
        ), 200)

    elif request.method == 'PATCH':
        depot = Depot.query.filter_by(id=id).first()
        if not depot:
            return make_response({"message":"Depot not found"})
        data = request.form or request.json
        if not data:
           return make_response({"message": "No data provided to update"}, 400) 
        for attr in data:
            if hasattr(depot, attr):
                setattr(depot, attr, data.get(attr))

        db.session.commit()
        depot_dict = depot.to_dict()
        return make_response(jsonify(depot_dict), 200)

#Transaction route
@app.route('/transaction', methods=['GET', 'POST'])
def getAllTransaction():
    if request.method == 'GET':
        transactions = []
        for transaction in Transaction.query.all():
            transaction_dict = transaction.to_dict()
            transactions.append(transaction_dict)
        return make_response(jsonify(transactions), 200)

    elif request.method == 'POST':
        data = request.json
        if not data:
            return make_response({"message": "Invalid JSON"}, 400)

        #check required fields
        required_fields = ["transcationType","quantity","unitPrice","totalPrice","depots_id","fertilizers_id"]
        for field in required_fields:
            if field not in data:
                return make_response({"message": f"Missing field: {field}"}, 400)
        new_transaction = Transaction(
            transcationType = data.get("transcationType"),
            quantity = data.get("quantity"),
            unitPrice =data.get("unitPrice"),
            totalPrice = data.get("totalPrice"),
            depots_id = data.get("depots_id"),
            fertilizers_id = data.get("fertilizers_id")

        )
        db.session.add(new_transaction)
        db.session.commit()
        transaction_dict = new_transaction.to_dict()
        return make_response(jsonify(transaction_dict), 201)

@app.route('/transaction/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
def transaction_by_id(id):
    transaction = Transaction.query.filter_by(id=id).first()
    if not transaction:
        return make_response({"message": "Transcation with id {id} not found"}, 404)
    if request.method == 'GET':
        transaction_dict = transaction.to_dict()
        return make_response(jsonify(transaction_dict), 200)

    elif  request.method == 'DELETE':
        transaction = Transaction.query.filter_by(id=id).first()
        if not transaction:
            return make_response(jsonify({
            "message": "data already deleted"
        }), 200)
        db.session.delete(transaction)
        db.session.commit()
        
        return make_response(jsonify({
            "delete_successful": True,
            "message": "transaction deleted"
        }), 200)

    elif request.method == 'PATCH':
        transaction = Transaction.query.filter_by(id=id).first()
        if not transaction:
            return make_response({"message":"Transaction not found"})
        data = request.form or request.json
        if not data:
            return make_response({"message": "No data provided to update"}, 400)
        for attr in data:
            if hasattr(transaction, attr):
                setattr(transaction, attr, data.get(attr))        
        
        
        db.session.commit()
        transaction_dict = transaction.to_dict()
        return make_response(jsonify(transaction_dict), 200)



if __name__ == "__main__":
    app.run(port=5000, debug=True)