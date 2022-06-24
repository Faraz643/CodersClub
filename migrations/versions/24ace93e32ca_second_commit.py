"""Second Commit

Revision ID: 24ace93e32ca
Revises: 70aad6fa95fd
Create Date: 2022-04-25 14:24:00.488553

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '24ace93e32ca'
down_revision = '70aad6fa95fd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('events', sa.Column('status', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('events', 'status')
    # ### end Alembic commands ###
