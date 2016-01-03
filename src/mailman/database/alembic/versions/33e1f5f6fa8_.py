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

"""Migration from Python 2 to Python 3.

Some columns changed from LargeBinary type to Unicode type.

Revision ID: 33e1f5f6fa8
Revises: 51b7f92bd06c
Create Date: 2015-01-20 17:32:30.144083

"""

__all__ = [
    'downgrade',
    'upgrade',
    ]


from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '33e1f5f6fa8'
down_revision = '51b7f92bd06c'


def upgrade():
    if op.get_bind().dialect.name != 'sqlite':
        # SQLite does not support altering columns.
        op.alter_column('message', 'message_id_hash', type_=sa.Unicode)
        op.alter_column('message', 'path', type_=sa.Unicode)
        op.alter_column('pended', 'token', type_=sa.Unicode)
        op.alter_column('_request', 'data_hash', type_=sa.Unicode)
        op.alter_column('user', 'password', type_=sa.Unicode)


def downgrade():
    if op.get_bind().dialect.name != 'sqlite':
        # SQLite does not support altering columns.
        op.alter_column('message', 'message_id_hash', type_=sa.LargeBinary)
        op.alter_column('message', 'path', type_=sa.LargeBinary)
        op.alter_column('pended', 'token', type_=sa.LargeBinary)
        op.alter_column('_request', 'data_hash', type_=sa.LargeBinary)
        op.alter_column('user', 'password', type_=sa.LargeBinary)
