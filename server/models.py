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

class NCPBStaff(db.Model, SerializerMixin):
    __tablename__ = "NCPBStaffs"
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(200), nullable=False)
    lastName = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    center = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phoneNumber = db.Column(db.Integer, nullable=False)
    department = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    depots_id = db.Column(db.Integer, db.ForeignKey('depots.id'))
  
class Fertilizer(db.Model, SerializerMixin):
    __tablename__ = "fertilizers"

    serialize_rules = ('-inventories.fertilizer', '-orders.fertilizer','-transactions.fertilizer',)
    serialize_only = ('id','name','Type','Price','ExpirationDate','NutrientComposition','Manufacturer','ApplicationMethod','ApplicationRate','PackagingSize','SafetyInformation','UsageInstructions','StorageConditions','EnvironmentalImpact','created_at','inventories','orders','transactions','supplier_id',)
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    Type = db.Column(db.String(100), nullable=False)
    NutrientComposition = db.Column(db.String(100), nullable=False)
    Manufacturer = db.Column(db.String(100), nullable=False)
    ApplicationMethod = db.Column(db.String(100), nullable=False)
    ApplicationRate = db.Column(db.String(100), nullable=False)
    PackagingSize = db.Column(db.String(100), nullable=False)
    Price = db.Column(db.Numeric(10,2), nullable=False)
    ExpirationDate = db.Column(db.String(100), nullable=False)
    SafetyInformation = db.Column(db.String(100), nullable=False)
    UsageInstructions = db.Column(db.String(100), nullable=False)
    StorageConditions = db.Column(db.String(100), nullable=False)
    EnvironmentalImpact = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    inventories = db.relationship('Inventory', backref='fertilizer', lazy='dynamic')
    orders = db.relationship('Order', backref='fertilizer', lazy='dynamic')
    transactions = db.relationship('Transaction', backref='fertilizer', lazy='dynamic')
    # suppliers = db.relationship('Supplier', backref='fertilizer')
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id', name='fk_fertilizers_supplier_id')) 
   

class Inventory(db.Model, SerializerMixin):
    __tablename__ = "inventories"
    serialize_only = ('id', 'stockQuantity', 'lastRestockedDate', 'depots_id', 'fertilizers_id',)
    id = db.Column(db.Integer, primary_key=True)
    stockQuantity = db.Column(db.Integer, nullable=False)
    lastRestockedDate = db.Column(db.String(100), nullable=False)
    depots_id = db.Column(db.Integer, db.ForeignKey('depots.id'))
    fertilizers_id = db.Column(db.Integer, db.ForeignKey('fertilizers.id'))
   

class Depot(db.Model, SerializerMixin):
    __tablename__ = "depots"
    serialize_rules = ('-NCPBStaffs.depot', '-transactions.depot', '-inventories.depot',)
    serialize_only = ('id', 'depotName', 'location', 'phoneNumber', 'email', 'managerName', 'storageCapacity',)
    id  = db.Column(db.Integer, primary_key=True)
    depotName = db.Column(db.String(150), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    phoneNumber = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    managerName = db.Column(db.String(200), nullable=False)
    storageCapacity = db.Column(db.Integer, nullable=False)
    depots = db.relationship('NCPBStaff', backref='depot', lazy='joined')
    inventories = db.relationship('Inventory', backref='depot', lazy='joined')
    transactions = db.relationship('Transaction', backref='depot', lazy='dynamic')
    
class Transaction(db.Model, SerializerMixin):
    __tablename__ = "transcations"
    serialize_rules = ('-depot.transactions', '-fertilizer.transactions',)
    serialize_only = ('id', 'transcationType', 'quantity', 'unitPrice', 'totalPrice', 'transcationDate', 'depots_id', 'fertilizers_id',)
    id = db.Column(db.Integer, primary_key=True)
    transcationType = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unitPrice = db.Column(db.Numeric(10,2), nullable=False)
    totalPrice = db.Column(db.Numeric(10,2), nullable=False)
    transcationDate = db.Column(db.DateTime(timezone=True), server_default=func.now())
    depots_id = db.Column(db.Integer, db.ForeignKey('depots.id'))
    fertilizers_id = db.Column(db.Integer, db.ForeignKey('fertilizers.id'))
    
class Order(db.Model, SerializerMixin):
    __tablename__ = "orders"

    serialize_rules = ('-payments.order', '-farmer.orders', '-fertilizer.orders',)
    serialize_only = ('id', 'quantity', 'totalPrice', 'paymentStatus', 'deliveryStatus', 'orderDate', 'farmers_id', 'fertilizers_id', 'payments',)
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)
    totalPrice = db.Column(db.Numeric(10,2), nullable=False)
    paymentStatus = db.Column(db.String(100), nullable=False)
    deliveryStatus = db.Column(db.String(100), nullable=False)
    orderDate = db.Column(db.DateTime(timezone=True), server_default=func.now())
    farmers_id = db.Column(db.Integer, db.ForeignKey('farmers.id'))
    fertilizers_id = db.Column(db.Integer, db.ForeignKey('fertilizers.id'))
    payments = db.relationship('Payment', backref='order') 

class Payment(db.Model, SerializerMixin):
    __tablename__ = "payments"
    serialize_only = ('id', 'amountPaid', 'paymentMethod', 'transcationReference', 'paymentDate', 'orders_id',)
    id = db.Column(db.Integer, primary_key=True)
    amountPaid = db.Column(db.Numeric(10,2), nullable=False)
    paymentMethod = db.Column(db.String(100), nullable=False)
    transcationReference = db.Column(db.String(100), nullable=False)
    paymentDate = db.Column(db.DateTime(timezone=True), server_default=func.now())
    orders_id = db.Column(db.Integer, db.ForeignKey('orders.id'))

class Supplier(db.Model, SerializerMixin):
    __tablename__ = "suppliers"
    serialize_rules = ('-fertilizers.supplier',)
    serialize_only = ('id', 'Name', 'phoneNumber', 'email', 'address', 'suppliedFertilizers', 'contractDetails', 'fertilizers',)
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100), nullable=False)
    phoneNumber = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    suppliedFertilizers = db.Column(db.String(100), nullable=False)
    contractDetails = db.Column(db.String(100), nullable=False)
    fertilizers = db.relationship('Fertilizer', backref='supplier')
