"""Initial Migration

Revision ID: 70aad6fa95fd
Revises: 
Create Date: 2022-04-24 11:40:02.619903

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '70aad6fa95fd'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('questions')
    op.add_column('participants', sa.Column('email', sa.String(), nullable=True))
    op.add_column('participants', sa.Column('branch', sa.String(), nullable=True))
    op.add_column('participants', sa.Column('semester', sa.String(), nullable=True))
    op.add_column('participants', sa.Column('contest', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('participants', 'contest')
    op.drop_column('participants', 'semester')
    op.drop_column('participants', 'branch')
    op.drop_column('participants', 'email')
    op.create_table('questions',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('question_title', sa.VARCHAR(), nullable=True),
    sa.Column('question_statement', sa.TEXT(), nullable=True),
    sa.Column('sample_input', sa.VARCHAR(), nullable=True),
    sa.Column('sample_output', sa.VARCHAR(), nullable=True),
    sa.Column('language', sa.VARCHAR(), nullable=True),
    sa.Column('level', sa.VARCHAR(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
