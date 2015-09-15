"""Workflow state table

Revision ID: 2bb9b382198
Revises: 16c2b25c7b
Create Date: 2015-03-25 18:09:18.338790

"""

# revision identifiers, used by Alembic.
revision = '2bb9b382198'
down_revision = '16c2b25c7b'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('workflowstate',
        sa.Column('name', sa.Unicode(), nullable=False),
        sa.Column('token', sa.Unicode(), nullable=False),
        sa.Column('step', sa.Unicode(), nullable=True),
        sa.Column('data', sa.Unicode(), nullable=True),
        sa.PrimaryKeyConstraint('name', 'token')
        )


def downgrade():
    op.drop_table('workflowstate')
