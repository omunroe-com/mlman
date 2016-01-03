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

"""Test mailman command utilities."""

__all__ = [
    'TestMailmanCommand',
    ]


import unittest

from io import StringIO
from mailman.bin.mailman import main
from unittest.mock import patch



class TestMailmanCommand(unittest.TestCase):
    def test_mailman_command_without_subcommand_prints_help(self):
        # Issue #137: Running `mailman` without a subcommand raises an
        # AttributeError.
        testargs = ['mailman']
        output = StringIO()
        with patch('sys.argv', testargs), patch('sys.stdout', output):
            with self.assertRaises(SystemExit):
                main()
        self.assertIn('usage', output.getvalue())
