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

"""Test users."""

__all__ = [
    'TestUser',
    ]


import unittest

from mailman.app.lifecycle import create_list
from mailman.config import config
from mailman.database.transaction import transaction
from mailman.interfaces.address import (
    AddressAlreadyLinkedError, AddressNotLinkedError)
from mailman.interfaces.user import UnverifiedAddressError
from mailman.interfaces.usermanager import IUserManager
from mailman.model.preferences import Preferences
from mailman.testing.layers import ConfigLayer
from mailman.utilities.datetime import now
from zope.component import getUtility



class TestUser(unittest.TestCase):
    """Test users."""

    layer = ConfigLayer

    def setUp(self):
        self._manager = getUtility(IUserManager)
        self._mlist = create_list('test@example.com')
        self._anne = self._manager.create_user(
            'anne@example.com', 'Anne Person')
        preferred = list(self._anne.addresses)[0]
        preferred.verified_on = now()
        self._anne.preferred_address = preferred

    def test_preferred_address_memberships(self):
        self._mlist.subscribe(self._anne)
        memberships = list(self._anne.memberships.members)
        self.assertEqual(len(memberships), 1)
        self.assertEqual(memberships[0].address.email, 'anne@example.com')
        self.assertEqual(memberships[0].user, self._anne)
        addresses = list(self._anne.memberships.addresses)
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0].email, 'anne@example.com')

    def test_preferred_and_address_memberships(self):
        self._mlist.subscribe(self._anne)
        aperson = self._anne.register('aperson@example.com')
        self._mlist.subscribe(aperson)
        memberships = list(self._anne.memberships.members)
        self.assertEqual(len(memberships), 2)
        self.assertEqual(set(member.address.email for member in memberships),
                         set(['anne@example.com', 'aperson@example.com']))
        self.assertEqual(memberships[0].user, memberships[1].user)
        self.assertEqual(memberships[0].user, self._anne)
        emails = set(address.email
                     for address in self._anne.memberships.addresses)
        self.assertEqual(len(emails), 2)
        self.assertEqual(emails,
                         set(['anne@example.com', 'aperson@example.com']))

    def test_uid_is_immutable(self):
        with self.assertRaises(AttributeError):
            self._anne.user_id = 'foo'

    def test_addresses_may_only_be_linked_to_one_user(self):
        user = self._manager.create_user()
        # Anne's preferred address is already linked to her.
        with self.assertRaises(AddressAlreadyLinkedError) as cm:
            user.link(self._anne.preferred_address)
        self.assertEqual(cm.exception.address, self._anne.preferred_address)

    def test_unlink_from_address_not_linked_to(self):
        # You cannot unlink an address from a user if that address is not
        # already linked to the user.
        user = self._manager.create_user()
        with self.assertRaises(AddressNotLinkedError) as cm:
            user.unlink(self._anne.preferred_address)
        self.assertEqual(cm.exception.address, self._anne.preferred_address)

    def test_unlink_address_which_is_not_linked(self):
        # You cannot unlink an address which is not linked to any user.
        address = self._manager.create_address('bart@example.com')
        user = self._manager.create_user()
        with self.assertRaises(AddressNotLinkedError) as cm:
            user.unlink(address)
        self.assertEqual(cm.exception.address, address)

    def test_set_unverified_preferred_address(self):
        # A user's preferred address cannot be set to an unverified address.
        new_preferred = self._manager.create_address(
            'anne.person@example.com')
        with self.assertRaises(UnverifiedAddressError) as cm:
            self._anne.preferred_address = new_preferred
        self.assertEqual(cm.exception.address, new_preferred)

    def test_preferences_deletion_on_user_deletion(self):
        # LP: #1418276 - deleting a user did not delete their preferences.
        with transaction():
            # This has to happen in a transaction so that both the user and
            # the preferences objects get valid ids.
            user = self._manager.create_user()
        # The user's preference is in the database.
        preferences = config.db.store.query(Preferences).filter_by(
            id=user.preferences.id)
        self.assertEqual(preferences.count(), 1)
        self._manager.delete_user(user)
        # The user's preference has been deleted.
        preferences = config.db.store.query(Preferences).filter_by(
            id=user.preferences.id)
        self.assertEqual(preferences.count(), 0)
