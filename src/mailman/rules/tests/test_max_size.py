# Copyright (C) 2016-2017 by the Free Software Foundation, Inc.
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

"""Test the `max_size` rule."""

import unittest

from mailman.app.lifecycle import create_list
from mailman.rules import max_size
from mailman.testing.helpers import specialized_message_from_string as mfs
from mailman.testing.layers import ConfigLayer


class TestMaximumSize(unittest.TestCase):
    """Test the max_size rule."""

    layer = ConfigLayer

    def setUp(self):
        self._mlist = create_list('test@example.com')

    def test_max_size_returns_reason(self):
        # Ensure max_size rule returns a reason.
        msg = mfs("""\
From: anne@example.com
To: test@example.com
Subject: A Subject
Message-ID: <ant>

A message body.
""")
        rule = max_size.MaximumSize()
        self._mlist.max_message_size = 1
        # Fake the size.
        msg.original_size = 2048
        msgdata = {}
        result = rule.check(self._mlist, msg, msgdata)
        self.assertTrue(result)
        self.assertEqual(msgdata['moderation_reasons'],
                         [('The message is larger than the {} KB maximum size',
                          1)])
