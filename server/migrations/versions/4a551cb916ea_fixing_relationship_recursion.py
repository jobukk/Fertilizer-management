"""fixing relationship recursion

Revision ID: 4a551cb916ea
Revises: 
Create Date: 2024-07-19 15:11:48.208579

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4a551cb916ea'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('depots',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('depotName', sa.String(length=150), nullable=False),
    sa.Column('location', sa.String(length=150), nullable=False),
    sa.Column('phoneNumber', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('managerName', sa.String(length=200), nullable=False),
    sa.Column('storageCapacity', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('farmers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('firstName', sa.String(length=100), nullable=False),
    sa.Column('lastName', sa.String(length=200), nullable=False),
    sa.Column('password', sa.String(length=250), nullable=False),
    sa.Column('phoneNumber', sa.Integer(), nullable=False),
    sa.Column('county', sa.String(length=100), nullable=False),
    sa.Column('subCounty', sa.String(length=100), nullable=False),
    sa.Column('farmSize', sa.String(length=150), nullable=False),
    sa.Column('cropType', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('suppliers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('Name', sa.String(length=100), nullable=False),
    sa.Column('phoneNumber', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('address', sa.String(length=100), nullable=False),
    sa.Column('suppliedFertilizers', sa.String(length=100), nullable=False),
    sa.Column('contractDetails', sa.String(length=100), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('NCPBStaffs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('firstName', sa.String(length=200), nullable=False),
    sa.Column('lastName', sa.String(length=200), nullable=False),
    sa.Column('role', sa.String(length=100), nullable=False),
    sa.Column('center', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=200), nullable=False),
    sa.Column('phoneNumber', sa.Integer(), nullable=False),
    sa.Column('department', sa.String(length=200), nullable=False),
    sa.Column('password', sa.String(length=250), nullable=False),
    sa.Column('depots_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['depots_id'], ['depots.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('fertilizers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('Type', sa.String(length=100), nullable=False),
    sa.Column('NutrientComposition', sa.String(length=100), nullable=False),
    sa.Column('Manufacturer', sa.String(length=100), nullable=False),
    sa.Column('ApplicationMethod', sa.String(length=100), nullable=False),
    sa.Column('ApplicationRate', sa.String(length=100), nullable=False),
    sa.Column('PackagingSize', sa.String(length=100), nullable=False),
    sa.Column('Price', sa.Numeric(precision=10, scale=2), nullable=False),
    sa.Column('ExpirationDate', sa.String(length=100), nullable=False),
    sa.Column('SafetyInformation', sa.String(length=100), nullable=False),
    sa.Column('UsageInstructions', sa.String(length=100), nullable=False),
    sa.Column('StorageConditions', sa.String(length=100), nullable=False),
    sa.Column('EnvironmentalImpact', sa.String(length=100), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.Column('supplier_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['supplier_id'], ['suppliers.id'], name='fk_fertilizers_supplier_id'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('inventories',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('stockQuantity', sa.Integer(), nullable=False),
    sa.Column('lastRestockedDate', sa.String(length=100), nullable=False),
    sa.Column('depots_id', sa.Integer(), nullable=True),
    sa.Column('fertilizers_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['depots_id'], ['depots.id'], ),
    sa.ForeignKeyConstraint(['fertilizers_id'], ['fertilizers.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('orders',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('totalPrice', sa.Numeric(precision=10, scale=2), nullable=False),
    sa.Column('paymentStatus', sa.String(length=100), nullable=False),
    sa.Column('deliveryStatus', sa.String(length=100), nullable=False),
    sa.Column('orderDate', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.Column('farmers_id', sa.Integer(), nullable=True),
    sa.Column('fertilizers_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['farmers_id'], ['farmers.id'], ),
    sa.ForeignKeyConstraint(['fertilizers_id'], ['fertilizers.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('transcations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('transcationType', sa.String(length=100), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('unitPrice', sa.Numeric(precision=10, scale=2), nullable=False),
    sa.Column('totalPrice', sa.Numeric(precision=10, scale=2), nullable=False),
    sa.Column('transcationDate', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.Column('depots_id', sa.Integer(), nullable=True),
    sa.Column('fertilizers_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['depots_id'], ['depots.id'], ),
    sa.ForeignKeyConstraint(['fertilizers_id'], ['fertilizers.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('payments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('amountPaid', sa.Numeric(precision=10, scale=2), nullable=False),
    sa.Column('paymentMethod', sa.String(length=100), nullable=False),
    sa.Column('transcationReference', sa.String(length=100), nullable=False),
    sa.Column('paymentDate', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.Column('orders_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['orders_id'], ['orders.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('payments')
    op.drop_table('transcations')
    op.drop_table('orders')
    op.drop_table('inventories')
    op.drop_table('fertilizers')
    op.drop_table('NCPBStaffs')
    op.drop_table('suppliers')
    op.drop_table('farmers')
    op.drop_table('depots')
    # ### end Alembic commands ###
