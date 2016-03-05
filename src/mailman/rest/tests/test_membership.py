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

"""REST membership tests."""

__all__ = [
    'TestMembership',
    'TestNonmembership',
    ]


import unittest

from mailman.app.lifecycle import create_list
from mailman.config import config
from mailman.database.transaction import transaction
from mailman.interfaces.member import MemberRole
from mailman.interfaces.usermanager import IUserManager
from mailman.testing.helpers import (
    TestableMaster, call_api, get_lmtp_client, make_testable_runner,
    wait_for_webservice)
from mailman.runners.incoming import IncomingRunner
from mailman.testing.layers import ConfigLayer, RESTLayer
from mailman.utilities.datetime import now
from urllib.error import HTTPError
from zope.component import getUtility


def _set_preferred(user):
    preferred = list(user.addresses)[0]
    preferred.verified_on = now()
    user.preferred_address = preferred



class TestMembership(unittest.TestCase):
    layer = RESTLayer

    def setUp(self):
        with transaction():
            self._mlist = create_list('test@example.com')
        self._usermanager = getUtility(IUserManager)

    def test_try_to_join_missing_list(self):
        # A user tries to join a non-existent list.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members', {
                'list_id': 'missing.example.com',
                'subscriber': 'nobody@example.com',
                })
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(cm.exception.reason, b'No such list')

    def test_try_to_leave_missing_list(self):
        # A user tries to leave a non-existent list.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/missing@example.com'
                     '/member/nobody@example.com',
                     method='DELETE')
        self.assertEqual(cm.exception.code, 404)

    def test_try_to_leave_list_with_bogus_address(self):
        # Try to leave a mailing list using an invalid membership address.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members/1', method='DELETE')
        self.assertEqual(cm.exception.code, 404)

    def test_try_to_leave_a_list_twice(self):
        with transaction():
            anne = self._usermanager.create_address('anne@example.com')
            self._mlist.subscribe(anne)
        url = 'http://localhost:9001/3.0/members/1'
        content, response = call_api(url, method='DELETE')
        # For a successful DELETE, the response code is 204 and there is no
        # content.
        self.assertEqual(content, None)
        self.assertEqual(response.status, 204)
        with self.assertRaises(HTTPError) as cm:
            call_api(url, method='DELETE')
        self.assertEqual(cm.exception.code, 404)

    def test_try_to_join_a_list_twice(self):
        with transaction():
            anne = self._usermanager.create_address('anne@example.com')
            self._mlist.subscribe(anne)
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members', {
                'list_id': 'test.example.com',
                'subscriber': 'anne@example.com',
                'pre_verified': True,
                'pre_confirmed': True,
                'pre_approved': True,
                })
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.reason, b'Member already subscribed')

    def test_add_member_with_mixed_case_email(self):
        # LP: #1425359 - Mailman is case-perserving, case-insensitive.  This
        # test subscribes the lower case address and ensures the original mixed
        # case address can't be subscribed.
        with transaction():
            anne = self._usermanager.create_address('anne@example.com')
            self._mlist.subscribe(anne)
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members', {
                'list_id': 'test.example.com',
                'subscriber': 'ANNE@example.com',
                'pre_verified': True,
                'pre_confirmed': True,
                'pre_approved': True,
                })
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.reason, b'Member already subscribed')

    def test_add_member_with_lower_case_email(self):
        # LP: #1425359 - Mailman is case-perserving, case-insensitive.  This
        # test subscribes the mixed case address and ensures the lower cased
        # address can't be added.
        with transaction():
            anne = self._usermanager.create_address('ANNE@example.com')
            self._mlist.subscribe(anne)
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members', {
                'list_id': 'test.example.com',
                'subscriber': 'anne@example.com',
                'pre_verified': True,
                'pre_confirmed': True,
                'pre_approved': True,
                })
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.reason, b'Member already subscribed')

    def test_join_with_invalid_delivery_mode(self):
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members', {
                'list_id': 'test.example.com',
                'subscriber': 'anne@example.com',
                'display_name': 'Anne Person',
                'delivery_mode': 'invalid-mode',
                })
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(cm.exception.reason,
                         b'Cannot convert parameters: delivery_mode')

    def test_join_email_contains_slash(self):
        content, response = call_api('http://localhost:9001/3.0/members', {
            'list_id': 'test.example.com',
            'subscriber': 'hugh/person@example.com',
            'display_name': 'Hugh Person',
            'pre_verified': True,
            'pre_confirmed': True,
            'pre_approved': True,
            })
        self.assertEqual(content, None)
        self.assertEqual(response.status, 201)
        self.assertEqual(response['location'],
                         'http://localhost:9001/3.0/members/1')
        # Reset any current transaction.
        config.db.abort()
        members = list(self._mlist.members.members)
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0].address.email, 'hugh/person@example.com')

    def test_join_as_user_with_preferred_address(self):
        with transaction():
            anne = self._usermanager.create_user('anne@example.com')
            _set_preferred(anne)
            self._mlist.subscribe(anne)
        content, response = call_api('http://localhost:9001/3.0/members')
        self.assertEqual(response.status, 200)
        self.assertEqual(int(content['total_size']), 1)
        entry_0 = content['entries'][0]
        self.assertEqual(entry_0['self_link'],
                         'http://localhost:9001/3.0/members/1')
        self.assertEqual(entry_0['role'], 'member')
        self.assertEqual(entry_0['user'], 'http://localhost:9001/3.0/users/1')
        self.assertEqual(entry_0['email'], 'anne@example.com')
        self.assertEqual(
            entry_0['address'],
            'http://localhost:9001/3.0/addresses/anne@example.com')
        self.assertEqual(entry_0['list_id'], 'test.example.com')

    def test_member_changes_preferred_address(self):
        with transaction():
            anne = self._usermanager.create_user('anne@example.com')
            _set_preferred(anne)
            self._mlist.subscribe(anne)
        # Take a look at Anne's current membership.
        content, response = call_api('http://localhost:9001/3.0/members')
        self.assertEqual(int(content['total_size']), 1)
        entry_0 = content['entries'][0]
        self.assertEqual(entry_0['email'], 'anne@example.com')
        self.assertEqual(
            entry_0['address'],
            'http://localhost:9001/3.0/addresses/anne@example.com')
        # Anne registers a new address and makes it her preferred address.
        # There are no changes to her membership.
        with transaction():
            new_preferred = anne.register('aperson@example.com')
            new_preferred.verified_on = now()
            anne.preferred_address = new_preferred
        # Take another look at Anne's current membership.
        content, response = call_api('http://localhost:9001/3.0/members')
        self.assertEqual(int(content['total_size']), 1)
        entry_0 = content['entries'][0]
        self.assertEqual(entry_0['email'], 'aperson@example.com')
        self.assertEqual(
            entry_0['address'],
            'http://localhost:9001/3.0/addresses/aperson@example.com')

    def test_get_nonexistent_member(self):
        # /members/<bogus> returns 404
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members/bogus')
        self.assertEqual(cm.exception.code, 404)

    def test_patch_nonexistent_member(self):
        # /members/<missing> PATCH returns 404
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members/801',
                     {}, method='PATCH')
        self.assertEqual(cm.exception.code, 404)

    def test_patch_member_bogus_attribute(self):
        # /members/<id> PATCH 'bogus' returns 400
        with transaction():
            anne = self._usermanager.create_address('anne@example.com')
            self._mlist.subscribe(anne)
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members/1', {
                     'powers': 'super',
                     }, method='PATCH')
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(cm.exception.reason, b'Unexpected parameters: powers')

    def test_member_all_without_preferences(self):
        # /members/<id>/all should return a 404 when it isn't trailed by
        # `preferences`
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members/1/all')
        self.assertEqual(cm.exception.code, 404)

    def test_subscribe_user_without_preferred_address(self):
        with transaction():
            getUtility(IUserManager).create_user('anne@example.com')
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members', {
                'list_id': 'test.example.com',
                'subscriber': 1,
                'pre_verified': True,
                'pre_confirmed': True,
                'pre_approved': True,
                })
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(cm.exception.reason, b'User has no preferred address')



class CustomLayer(ConfigLayer):
    """Custom layer which starts both the REST and LMTP servers."""

    server = None
    client = None

    @classmethod
    def _wait_for_both(cls):
        cls.client = get_lmtp_client(quiet=True)
        wait_for_webservice()

    @classmethod
    def setUp(cls):
        assert cls.server is None, 'Layer already set up'
        cls.server = TestableMaster(cls._wait_for_both)
        cls.server.start('lmtp', 'rest')

    @classmethod
    def tearDown(cls):
        assert cls.server is not None, 'Layer is not set up'
        cls.server.stop()
        cls.server = None


class TestNonmembership(unittest.TestCase):
    layer = CustomLayer

    def setUp(self):
        with transaction():
            self._mlist = create_list('test@example.com')
        self._usermanager = getUtility(IUserManager)

    def _go(self, message):
        lmtp = get_lmtp_client(quiet=True)
        lmtp.lhlo('remote.example.org')
        lmtp.sendmail('nonmember@example.com', ['test@example.com'], message)
        lmtp.close()
        # The message will now be sitting in the `in` queue.  Run the incoming
        # runner once to process it, which should result in the nonmember
        # showing up.
        inq = make_testable_runner(IncomingRunner, 'in')
        inq.run()

    def test_nonmember_findable_after_posting(self):
        # A nonmember we have never seen before posts a message to the mailing
        # list.  They are findable through the /members/find API using a role
        # of nonmember.
        self._go("""\
From: nonmember@example.com
To: test@example.com
Subject: Nonmember post
Message-ID: <alpha>

Some text.
""")
        # Now use the REST API to try to find the nonmember.
        response, content = call_api(
            'http://localhost:9001/3.0/members/find', {
                #'list_id': 'test.example.com',
                'role': 'nonmember',
                })
        self.assertEqual(response['total_size'], 1)
        nonmember = response['entries'][0]
        self.assertEqual(nonmember['role'], 'nonmember')
        self.assertEqual(nonmember['email'], 'nonmember@example.com')
        self.assertEqual(
            nonmember['address'],
            'http://localhost:9001/3.0/addresses/nonmember@example.com')
        # There is no user key in the JSON data because there is no user
        # record associated with the address record.
        self.assertNotIn('user', nonmember)

    def test_linked_nonmember_findable_after_posting(self):
        # Like above, a nonmember posts a message to the mailing list.  In
        # this case though, the nonmember already has a user record.  They are
        # findable through the /members/find API using a role of nonmember.
        with transaction():
            self._usermanager.create_user('nonmember@example.com')
        self._go("""\
From: nonmember@example.com
To: test@example.com
Subject: Nonmember post
Message-ID: <alpha>

Some text.
""")
        # Now use the REST API to try to find the nonmember.
        response, content = call_api(
            'http://localhost:9001/3.0/members/find', {
                #'list_id': 'test.example.com',
                'role': 'nonmember',
                })
        self.assertEqual(response['total_size'], 1)
        nonmember = response['entries'][0]
        self.assertEqual(nonmember['role'], 'nonmember')
        self.assertEqual(nonmember['email'], 'nonmember@example.com')
        self.assertEqual(
            nonmember['address'],
            'http://localhost:9001/3.0/addresses/nonmember@example.com')
        # There is a user key in the JSON data because the address had
        # previously been linked to a user record.
        self.assertEqual(nonmember['user'],
                         'http://localhost:9001/3.0/users/1')

    def test_duplicate_owner(self):
        # Server failure when someone is already an owner.
        with transaction():
            anne = getUtility(IUserManager).create_address('anne@example.com')
            self._mlist.subscribe(anne, MemberRole.owner)
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/members', {
                'list_id': 'test.example.com',
                'subscriber': anne.email,
                'role': 'owner',
                })
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(
            cm.exception.reason,
            b'anne@example.com is already an owner of test@example.com')
