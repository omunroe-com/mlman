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

"""Test the high level list lifecycle API."""

__all__ = [
    'TestLifecycle',
    ]


import os
import shutil
import unittest

from mailman.config import config
from mailman.interfaces.address import InvalidEmailAddressError
from mailman.interfaces.domain import BadDomainSpecificationError
from mailman.app.lifecycle import create_list, remove_list
from mailman.testing.layers import ConfigLayer



class TestLifecycle(unittest.TestCase):
    """Test the high level list lifecycle API."""

    layer = ConfigLayer

    def test_posting_address_validation(self):
        # Creating a mailing list with a bogus address raises an exception.
        self.assertRaises(InvalidEmailAddressError,
                          create_list, 'bogus address')

    def test_unregistered_domain(self):
        # Creating a list with an unregistered domain raises an exception.
        self.assertRaises(BadDomainSpecificationError,
                     create_list, 'test@nodomain.example.org')

    def test_remove_list_error(self):
        # An error occurs while deleting the list's data directory.
        mlist = create_list('test@example.com')
        data_dir = os.path.join(config.LIST_DATA_DIR, mlist.fqdn_listname)
        os.chmod(data_dir, 0)
        self.addCleanup(shutil.rmtree, data_dir)
        self.assertRaises(OSError, remove_list, mlist)
        os.chmod(data_dir, 0o777)
