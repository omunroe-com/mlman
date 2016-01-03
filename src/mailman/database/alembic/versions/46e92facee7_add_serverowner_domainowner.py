# Copyright (C) 2015-2016 by the Free Software Foundation, Inc.
#
# This file is part of GNU Mailman.
#
# GNU Mailman is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# GNU Mailman is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# GNU Mailman.  If not, see <http://www.gnu.org/licenses/>.

"""add_serverowner_domainowner

Revision ID: 46e92facee7
Revises: 33e1f5f6fa8
Create Date: 2015-03-20 16:01:25.007242

"""

# Revision identifiers, used by Alembic.
revision = '46e92facee7'
down_revision = '33e1f5f6fa8'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'domain_owner',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('domain_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['domain_id'], ['domain.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('user_id', 'domain_id')
        )
    op.add_column(
        'user',
        sa.Column('is_server_owner', sa.Boolean(), nullable=True))
    if op.get_bind().dialect.name != 'sqlite':
        op.drop_column('domain', 'contact_address')


def downgrade():
    if op.get_bind().dialect.name != 'sqlite':
        op.drop_column('user', 'is_server_owner')
        op.add_column(
            'domain',
            sa.Column('contact_address', sa.VARCHAR(), nullable=True))
    op.drop_table('domain_owner')
