# Copyright (C) 2011-2016 by the Free Software Foundation, Inc.
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

"""Bounce support."""

__all__ = [
    'BounceEvent',
    'BounceProcessor',
    ]



from mailman.database.model import Model
from mailman.database.transaction import dbconnection
from mailman.database.types import Enum
from mailman.interfaces.bounce import (
    BounceContext, IBounceEvent, IBounceProcessor)
from mailman.utilities.datetime import now
from sqlalchemy import Boolean, Column, DateTime, Integer, Unicode
from zope.interface import implementer



@implementer(IBounceEvent)
class BounceEvent(Model):
    """See `IBounceEvent`."""

    __tablename__ = 'bounceevent'

    id = Column(Integer, primary_key=True)
    list_id = Column(Unicode)
    email = Column(Unicode)
    timestamp = Column(DateTime)
    message_id = Column(Unicode)
    context = Column(Enum(BounceContext))
    processed = Column(Boolean)

    def __init__(self, list_id, email, msg, context=None):
        self.list_id = list_id
        self.email = email
        self.timestamp = now()
        msgid = msg['message-id']
        if isinstance(msgid, bytes):
            msgid = msgid.decode('ascii')
        self.message_id = msgid
        self.context = (BounceContext.normal if context is None else context)
        self.processed = False



@implementer(IBounceProcessor)
class BounceProcessor:
    """See `IBounceProcessor`."""

    @dbconnection
    def register(self, store, mlist, email, msg, where=None):
        """See `IBounceProcessor`."""
        event = BounceEvent(mlist.list_id, email, msg, where)
        store.add(event)
        return event

    @property
    @dbconnection
    def events(self, store):
        """See `IBounceProcessor`."""
        for event in store.query(BounceEvent).all():
            yield event

    @property
    @dbconnection
    def unprocessed(self, store):
        """See `IBounceProcessor`."""
        for event in store.query(BounceEvent).filter_by(processed=False):
            yield event
