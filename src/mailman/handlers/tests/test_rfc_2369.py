# Copyright (C) 2015 by the Free Software Foundation, Inc.
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

"""Test the rfc_2369 handler."""

__all__ = [
    'TestRFC2369',
    ]


import unittest

from mailman.app.lifecycle import create_list
from mailman.config import config
from mailman.handlers import rfc_2369
from mailman.interfaces.archiver import ArchivePolicy, IArchiver
from mailman.testing.helpers import specialized_message_from_string as mfs
from mailman.testing.layers import ConfigLayer
from urllib.parse import urljoin
from zope.interface import implementer



@implementer(IArchiver)
class DummyArchiver:
    """An example archiver which does nothing but return URLs."""
    name = 'dummy'

    def list_url(self, mlist):
        """See `IArchiver`."""
        return mlist.domain.base_url

    def permalink(self, mlist, msg):
        """See `IArchiver`."""
        message_id_hash = msg.get('message-id-hash')
        if message_id_hash is None:
            return None
        return urljoin(self.list_url(mlist), message_id_hash)

    @staticmethod
    def archive_message(mlist, message):
        return None



class TestRFC2369(unittest.TestCase):
    """Test the rfc_2369 handler."""

    layer = ConfigLayer

    def setUp(self):
        config.push('no_archivers', """
        [archiver.prototype]
        enable: no
        [archiver.mail_archive]
        enable: no
        [archiver.mhonarc]
        enable: no
        [archiver.pipermail]
        enable: no
        """)
        self.addCleanup(config.pop, 'no_archivers')
        self._mlist = create_list('test@example.com')
        self._mlist.archive_policy = ArchivePolicy.public
        self._msg = mfs("""\
From: aperson@example.com
Message-ID: <first>
Message-ID-Hash: 4CMWUN6BHVCMHMDAOSJZ2Q72G5M32MWB

Dummy text
""")

    def test_add_headers(self):
        # Test the addition of the Archived-At and List-Archive headers.
        config.push('archiver', """
        [archiver.dummy]
        class: {}.DummyArchiver
        enable: yes
        """.format(DummyArchiver.__module__))
        self.addCleanup(config.pop, 'archiver')
        rfc_2369.process(self._mlist, self._msg, {})
        self.assertEqual(
            self._msg.get_all('List-Archive'),
            ['<http://lists.example.com>'])
        self.assertEqual(
            self._msg.get_all('Archived-At'),
            ['<http://lists.example.com/4CMWUN6BHVCMHMDAOSJZ2Q72G5M32MWB>'])

    def test_prototype_no_url(self):
        # The prototype archiver is not web-based, it must not return URLs
        config.push('archiver', """
        [archiver.prototype]
        enable: yes
        """)
        self.addCleanup(config.pop, 'archiver')
        rfc_2369.process(self._mlist, self._msg, {})
        self.assertNotIn('Archived-At', self._msg)
        self.assertNotIn('List-Archive', self._msg)

    def test_not_archived(self):
        # Messages sent to non-archived lists must not get the added headers.
        self._mlist.archive_policy = ArchivePolicy.never
        config.push('archiver', """
        [archiver.dummy]
        class: {}.DummyArchiver
        enable: yes
        """.format(DummyArchiver.__module__))
        self.addCleanup(config.pop, 'archiver')
        rfc_2369.process(self._mlist, self._msg, {})
        self.assertNotIn('List-Archive', self._msg)
        self.assertNotIn('Archived-At', self._msg)
