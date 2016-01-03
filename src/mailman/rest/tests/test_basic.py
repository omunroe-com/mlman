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

"""Test basic functionality of the REST API.

For example, test the integration between Mailman and Falcon.
"""

__all__ = [
    'TestBasicREST',
    ]


import unittest

from mailman.app.lifecycle import create_list
from mailman.database.transaction import transaction
from mailman.testing.helpers import call_api
from mailman.testing.layers import RESTLayer



class TestBasicREST(unittest.TestCase):
    """Test basic REST integration and functionality."""

    layer = RESTLayer

    def setUp(self):
        with transaction():
            self._mlist = create_list('test@example.com')

    def test_comma_fields(self):
        resource, response = call_api(
            'http://localhost:9001/3.0/lists/test@example.com/config',
            dict(description='A description with , to check stuff'),
            method='PATCH')
        # This fails with Falcon 0.2; passes with Falcon 0.3.
        self.assertEqual(self._mlist.description,
                         'A description with , to check stuff')
