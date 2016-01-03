# Copyright (C) 2012-2016 by the Free Software Foundation, Inc.
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

"""REST moderation tests."""

__all__ = [
    'TestPostModeration',
    'TestSubscriptionModeration',
    ]


import unittest

from mailman.app.lifecycle import create_list
from mailman.app.moderator import hold_message
from mailman.database.transaction import transaction
from mailman.interfaces.mailinglist import SubscriptionPolicy
from mailman.interfaces.registrar import IRegistrar
from mailman.interfaces.usermanager import IUserManager
from mailman.testing.helpers import (
    call_api, get_queue_messages, specialized_message_from_string as mfs)
from mailman.testing.layers import RESTLayer
from mailman.utilities.datetime import now
from urllib.error import HTTPError
from zope.component import getUtility



class TestPostModeration(unittest.TestCase):
    layer = RESTLayer

    def setUp(self):
        with transaction():
            self._mlist = create_list('ant@example.com')
        self._msg = mfs("""\
From: anne@example.com
To: ant@example.com
Subject: Something
Message-ID: <alpha>

Something else.
""")

    def test_not_found(self):
        # When a bogus mailing list is given, 404 should result.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/bee@example.com/held')
        self.assertEqual(cm.exception.code, 404)

    def test_bad_held_message_request_id(self):
        # Bad request when request_id is not an integer.
        with self.assertRaises(HTTPError) as cm:
            call_api(
                'http://localhost:9001/3.0/lists/ant@example.com/held/bogus')
        self.assertEqual(cm.exception.code, 400)

    def test_missing_held_message_request_id(self):
        # Not found when the request_id is not in the database.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/ant@example.com/held/99')
        self.assertEqual(cm.exception.code, 404)

    def test_bad_held_message_action(self):
        # POSTing to a held message with a bad action.
        held_id = hold_message(self._mlist, self._msg)
        url = 'http://localhost:9001/3.0/lists/ant@example.com/held/{0}'
        with self.assertRaises(HTTPError) as cm:
            call_api(url.format(held_id), {'action': 'bogus'})
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(cm.exception.msg,
                         b'Cannot convert parameters: action')

    def test_discard(self):
        # Discarding a message removes it from the moderation queue.
        with transaction():
            held_id = hold_message(self._mlist, self._msg)
        url = 'http://localhost:9001/3.0/lists/ant@example.com/held/{}'.format(
            held_id)
        content, response = call_api(url, dict(action='discard'))
        self.assertEqual(response.status, 204)
        # Now it's gone.
        with self.assertRaises(HTTPError) as cm:
            call_api(url, dict(action='discard'))
        self.assertEqual(cm.exception.code, 404)



class TestSubscriptionModeration(unittest.TestCase):
    layer = RESTLayer
    maxDiff = None

    def setUp(self):
        with transaction():
            self._mlist = create_list('ant@example.com')
            self._registrar = IRegistrar(self._mlist)
            manager = getUtility(IUserManager)
            self._anne = manager.create_address(
                'anne@example.com', 'Anne Person')
            self._bart = manager.make_user(
                'bart@example.com', 'Bart Person')
            preferred = list(self._bart.addresses)[0]
            preferred.verified_on = now()
            self._bart.preferred_address = preferred

    def test_no_such_list(self):
        # Try to get the requests of a nonexistent list.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/bee@example.com/'
                     'requests')
        self.assertEqual(cm.exception.code, 404)

    def test_no_such_subscription_token(self):
        # Bad request when the token is not in the database.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/ant@example.com/'
                     'requests/missing')
        self.assertEqual(cm.exception.code, 404)

    def test_bad_subscription_action(self):
        # POSTing to a held message with a bad action.
        token, token_owner, member = self._registrar.register(self._anne)
        # Anne's subscription request got held.
        self.assertIsNone(member)
        # Let's try to handle her request, but with a bogus action.
        url = 'http://localhost:9001/3.0/lists/ant@example.com/requests/{}'
        with self.assertRaises(HTTPError) as cm:
            call_api(url.format(token), dict(
                action='bogus',
                ))
        self.assertEqual(cm.exception.code, 400)
        self.assertEqual(cm.exception.msg,
                         b'Cannot convert parameters: action')

    def test_list_held_requests(self):
        # We can view all the held requests.
        with transaction():
            token_1, token_owner, member = self._registrar.register(self._anne)
            # Anne's subscription request got held.
            self.assertIsNotNone(token_1)
            self.assertIsNone(member)
            token_2, token_owner, member = self._registrar.register(self._bart)
            self.assertIsNotNone(token_2)
            self.assertIsNone(member)
        content, response = call_api(
            'http://localhost:9001/3.0/lists/ant@example.com/requests')
        self.assertEqual(response.status, 200)
        self.assertEqual(content['total_size'], 2)
        tokens = set(json['token'] for json in content['entries'])
        self.assertEqual(tokens, {token_1, token_2})
        emails = set(json['email'] for json in content['entries'])
        self.assertEqual(emails, {'anne@example.com', 'bart@example.com'})

    def test_individual_request(self):
        # We can view an individual request.
        with transaction():
            token, token_owner, member = self._registrar.register(self._anne)
            # Anne's subscription request got held.
            self.assertIsNotNone(token)
            self.assertIsNone(member)
        url = 'http://localhost:9001/3.0/lists/ant@example.com/requests/{}'
        content, response = call_api(url.format(token))
        self.assertEqual(response.status, 200)
        self.assertEqual(content['token'], token)
        self.assertEqual(content['token_owner'], token_owner.name)
        self.assertEqual(content['email'], 'anne@example.com')

    def test_accept(self):
        # POST to the request to accept it.
        with transaction():
            token, token_owner, member = self._registrar.register(self._anne)
        # Anne's subscription request got held.
        self.assertIsNone(member)
        url = 'http://localhost:9001/3.0/lists/ant@example.com/requests/{}'
        content, response = call_api(url.format(token), dict(
            action='accept',
            ))
        self.assertEqual(response.status, 204)
        # Anne is a member.
        self.assertEqual(
            self._mlist.members.get_member('anne@example.com').address,
            self._anne)
        # The request URL no longer exists.
        with self.assertRaises(HTTPError) as cm:
            call_api(url.format(token), dict(
                action='accept',
                ))
        self.assertEqual(cm.exception.code, 404)

    def test_accept_bad_token(self):
        # Try to accept a request with a bogus token.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/ant@example.com'
                     '/requests/bogus',
                     dict(action='accept'))
        self.assertEqual(cm.exception.code, 404)

    def test_accept_by_moderator_clears_request_queue(self):
        # After accepting a message held for moderator approval, there are no
        # more requests to handle.
        #
        # We start with nothing in the queue.
        content, response = call_api(
            'http://localhost:9001/3.0/lists/ant@example.com/requests')
        self.assertEqual(content['total_size'], 0)
        # Anne tries to subscribe to a list that only requests moderator
        # approval.
        with transaction():
            self._mlist.subscription_policy = SubscriptionPolicy.moderate
            token, token_owner, member = self._registrar.register(
                self._anne,
                pre_verified=True, pre_confirmed=True)
        # There's now one request in the queue, and it's waiting on moderator
        # approval.
        content, response = call_api(
            'http://localhost:9001/3.0/lists/ant@example.com/requests')
        self.assertEqual(content['total_size'], 1)
        json = content['entries'][0]
        self.assertEqual(json['token_owner'], 'moderator')
        self.assertEqual(json['email'], 'anne@example.com')
        # The moderator approves the request.
        url = 'http://localhost:9001/3.0/lists/ant@example.com/requests/{}'
        content, response = call_api(url.format(token), {'action': 'accept'})
        self.assertEqual(response.status, 204)
        # And now the request queue is empty.
        content, response = call_api(
            'http://localhost:9001/3.0/lists/ant@example.com/requests')
        self.assertEqual(content['total_size'], 0)

    def test_discard(self):
        # POST to the request to discard it.
        with transaction():
            token, token_owner, member = self._registrar.register(self._anne)
        # Anne's subscription request got held.
        self.assertIsNone(member)
        url = 'http://localhost:9001/3.0/lists/ant@example.com/requests/{}'
        content, response = call_api(url.format(token), dict(
            action='discard',
            ))
        self.assertEqual(response.status, 204)
        # Anne is not a member.
        self.assertIsNone(self._mlist.members.get_member('anne@example.com'))
        # The request URL no longer exists.
        with self.assertRaises(HTTPError) as cm:
            call_api(url.format(token), dict(
                action='discard',
                ))
        self.assertEqual(cm.exception.code, 404)

    def test_defer(self):
        # Defer the decision for some other moderator.
        with transaction():
            token, token_owner, member = self._registrar.register(self._anne)
        # Anne's subscription request got held.
        self.assertIsNone(member)
        url = 'http://localhost:9001/3.0/lists/ant@example.com/requests/{}'
        content, response = call_api(url.format(token), dict(
            action='defer',
            ))
        self.assertEqual(response.status, 204)
        # Anne is not a member.
        self.assertIsNone(self._mlist.members.get_member('anne@example.com'))
        # The request URL still exists.
        content, response = call_api(url.format(token), dict(
            action='defer',
            ))
        self.assertEqual(response.status, 204)
        # And now we can accept it.
        content, response = call_api(url.format(token), dict(
            action='accept',
            ))
        self.assertEqual(response.status, 204)
        # Anne is a member.
        self.assertEqual(
            self._mlist.members.get_member('anne@example.com').address,
            self._anne)
        # The request URL no longer exists.
        with self.assertRaises(HTTPError) as cm:
            call_api(url.format(token), dict(
                action='accept',
                ))
        self.assertEqual(cm.exception.code, 404)

    def test_defer_bad_token(self):
        # Try to accept a request with a bogus token.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/ant@example.com'
                     '/requests/bogus',
                     dict(action='defer'))
        self.assertEqual(cm.exception.code, 404)

    def test_reject(self):
        # POST to the request to reject it.  This leaves a bounce message in
        # the virgin queue.
        with transaction():
            token, token_owner, member = self._registrar.register(self._anne)
        # Anne's subscription request got held.
        self.assertIsNone(member)
        # Clear out the virgin queue, which currently contains the
        # confirmation message sent to Anne.
        get_queue_messages('virgin')
        url = 'http://localhost:9001/3.0/lists/ant@example.com/requests/{}'
        content, response = call_api(url.format(token), dict(
            action='reject',
            ))
        self.assertEqual(response.status, 204)
        # Anne is not a member.
        self.assertIsNone(self._mlist.members.get_member('anne@example.com'))
        # The request URL no longer exists.
        with self.assertRaises(HTTPError) as cm:
            call_api(url.format(token), dict(
                action='reject',
                ))
        self.assertEqual(cm.exception.code, 404)
        # And the rejection message to Anne is now in the virgin queue.
        items = get_queue_messages('virgin')
        self.assertEqual(len(items), 1)
        message = items[0].msg
        self.assertEqual(message['From'], 'ant-bounces@example.com')
        self.assertEqual(message['To'], 'anne@example.com')
        self.assertEqual(message['Subject'],
                         'Request to mailing list "Ant" rejected')

    def test_reject_bad_token(self):
        # Try to accept a request with a bogus token.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/lists/ant@example.com'
                     '/requests/bogus',
                     dict(action='reject'))
        self.assertEqual(cm.exception.code, 404)
