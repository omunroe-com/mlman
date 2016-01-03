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

"""REST root object tests."""

__all__ = [
    'TestRoot',
    ]


import os
import json
import unittest

from base64 import b64encode
from httplib2 import Http
from mailman.config import config
from mailman.core.system import system
from mailman.testing.helpers import call_api
from mailman.testing.layers import RESTLayer
from urllib.error import HTTPError



class TestRoot(unittest.TestCase):
    layer = RESTLayer

    def test_root_system_backward_compatibility(self):
        # The deprecated path for getting system version information points
        # you to the new URL.
        url = 'http://localhost:9001/3.0/system'
        new = '{}/versions'.format(url)
        json, response = call_api(url)
        self.assertEqual(json['mailman_version'], system.mailman_version)
        self.assertEqual(json['python_version'], system.python_version)
        self.assertEqual(json['self_link'], new)

    def test_system_versions(self):
        # System version information is available via REST.
        url = 'http://localhost:9001/3.0/system/versions'
        json, response = call_api(url)
        self.assertEqual(json['mailman_version'], system.mailman_version)
        self.assertEqual(json['python_version'], system.python_version)
        self.assertEqual(json['self_link'], url)

    def test_path_under_root_does_not_exist(self):
        # Accessing a non-existent path under root returns a 404.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/does-not-exist')
        self.assertEqual(cm.exception.code, 404)

    def test_system_url_not_preferences(self):
        # /system/foo where `foo` is not `preferences`.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/system/foo')
        self.assertEqual(cm.exception.code, 404)

    def test_system_preferences_are_read_only(self):
        # /system/preferences are read-only.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/system/preferences', {
                     'acknowledge_posts': True,
                     }, method='PATCH')
        self.assertEqual(cm.exception.code, 405)
        # /system/preferences are read-only.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/system/preferences', {
                'acknowledge_posts': False,
                'delivery_mode': 'regular',
                'delivery_status': 'enabled',
                'hide_address': True,
                'preferred_language': 'en',
                'receive_list_copy': True,
                'receive_own_postings': True,
                }, method='PUT')
        self.assertEqual(cm.exception.code, 405)

    def test_queue_directory(self):
        # The REST runner is not queue runner, so it should not have a
        # directory in var/queue.
        queue_directory = os.path.join(config.QUEUE_DIR, 'rest')
        self.assertFalse(os.path.isdir(queue_directory))

    def test_no_basic_auth(self):
        # If Basic Auth credentials are missing, it is a 401 error.
        url = 'http://localhost:9001/3.0/system'
        headers = {
            'Content-Type': 'application/x-www-form-urlencode',
            }
        response, raw_content = Http().request(url, 'GET', None, headers)
        self.assertEqual(response.status, 401)
        content = json.loads(raw_content.decode('utf-8'))
        self.assertEqual(content['title'], '401 Unauthorized')
        self.assertEqual(content['description'],
                         'The REST API requires authentication')

    def test_unauthorized(self):
        # Bad Basic Auth credentials results in a 401 error.
        userpass = b64encode(b'baduser:badpass')
        auth = 'Basic {}'.format(userpass.decode('ascii'))
        url = 'http://localhost:9001/3.0/system'
        headers = {
            'Content-Type': 'application/x-www-form-urlencode',
            'Authorization': auth,
            }
        response, raw_content = Http().request(url, 'GET', None, headers)
        self.assertEqual(response.status, 401)
        content = json.loads(raw_content.decode('utf-8'))
        self.assertEqual(content['title'], '401 Unauthorized')
        self.assertEqual(content['description'],
                         'User is not authorized for the REST API')

    def test_reserved_bad_subpath(self):
        # Only <api>/reserved/uids/orphans is a defined resource.  DELETEing
        # anything else gives a 404.
        with self.assertRaises(HTTPError) as cm:
            call_api('http://localhost:9001/3.0/reserved/uids/assigned',
                     method='DELETE')
        self.assertEqual(cm.exception.code, 404)
