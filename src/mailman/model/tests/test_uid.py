# Copyright (C) 2011 by the Free Software Foundation, Inc.
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

"""Test the UID model class."""

from __future__ import absolute_import, unicode_literals

__metaclass__ = type
__all__ = [
    'test_suite',
    ]


import unittest

from mailman.model.uid import UID
from mailman.testing.layers import ConfigLayer



class TestUID(unittest.TestCase):
    layer = ConfigLayer

    def test_record(self):
        UID.record('abc')
        UID.record('def')
        self.assertRaises(ValueError, UID.record, 'abc')



def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestUID))
    return suite