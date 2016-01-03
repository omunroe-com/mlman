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

"""Test the template downloader API."""

__all__ = [
    'TestTemplateLoader',
    ]


import os
import shutil
import tempfile
import unittest

from mailman.app.lifecycle import create_list
from mailman.config import config
from mailman.interfaces.languages import ILanguageManager
from mailman.interfaces.templates import ITemplateLoader
from mailman.testing.layers import ConfigLayer
from urllib.error import URLError
from zope.component import getUtility



class TestTemplateLoader(unittest.TestCase):
    """Test the template downloader API."""

    layer = ConfigLayer

    def setUp(self):
        self.var_dir = tempfile.mkdtemp()
        config.push('template config', """\
        [paths.testing]
        var_dir: {0}
        """.format(self.var_dir))
        # Put a demo template in the site directory.
        path = os.path.join(self.var_dir, 'templates', 'site', 'en')
        os.makedirs(path)
        with open(os.path.join(path, 'demo.txt'), 'w') as fp:
            print('Test content', end='', file=fp)
        self._loader = getUtility(ITemplateLoader)
        getUtility(ILanguageManager).add('it', 'utf-8', 'Italian')
        self._mlist = create_list('test@example.com')

    def tearDown(self):
        config.pop('template config')
        shutil.rmtree(self.var_dir)

    def test_mailman_internal_uris(self):
        # mailman://demo.txt
        content = self._loader.get('mailman:///demo.txt')
        self.assertEqual(content, 'Test content')

    def test_mailman_internal_uris_twice(self):
        # mailman:///demo.txt
        content = self._loader.get('mailman:///demo.txt')
        self.assertEqual(content, 'Test content')
        content = self._loader.get('mailman:///demo.txt')
        self.assertEqual(content, 'Test content')

    def test_mailman_uri_with_language(self):
        content = self._loader.get('mailman:///en/demo.txt')
        self.assertEqual(content, 'Test content')

    def test_mailman_uri_with_english_fallback(self):
        content = self._loader.get('mailman:///it/demo.txt')
        self.assertEqual(content, 'Test content')

    def test_mailman_uri_with_list_name(self):
        content = self._loader.get('mailman:///test@example.com/demo.txt')
        self.assertEqual(content, 'Test content')

    def test_mailman_full_uri(self):
        content = self._loader.get('mailman:///test@example.com/en/demo.txt')
        self.assertEqual(content, 'Test content')

    def test_mailman_full_uri_with_english_fallback(self):
        content = self._loader.get('mailman:///test@example.com/it/demo.txt')
        self.assertEqual(content, 'Test content')

    def test_uri_not_found(self):
        with self.assertRaises(URLError) as cm:
            self._loader.get('mailman:///missing.txt')
        self.assertEqual(cm.exception.reason, 'No such file')

    def test_shorter_url_error(self):
        with self.assertRaises(URLError) as cm:
            self._loader.get('mailman:///')
        self.assertEqual(cm.exception.reason, 'No template specified')

    def test_short_url_error(self):
        with self.assertRaises(URLError) as cm:
            self._loader.get('mailman://')
        self.assertEqual(cm.exception.reason, 'No template specified')

    def test_bad_language(self):
        with self.assertRaises(URLError) as cm:
            self._loader.get('mailman:///xx/demo.txt')
        self.assertEqual(cm.exception.reason, 'Bad language or list name')

    def test_bad_mailing_list(self):
        with self.assertRaises(URLError) as cm:
            self._loader.get('mailman:///missing@example.com/demo.txt')
        self.assertEqual(cm.exception.reason, 'Bad language or list name')

    def test_too_many_path_components(self):
        with self.assertRaises(URLError) as cm:
            self._loader.get('mailman:///missing@example.com/en/foo/demo.txt')
        self.assertEqual(cm.exception.reason, 'No such file')

    def test_non_ascii(self):
        # mailman://demo.txt with non-ascii content.
        test_text = b'\xe4\xb8\xad'
        path = os.path.join(self.var_dir, 'templates', 'site', 'it')
        os.makedirs(path)
        with open(os.path.join(path, 'demo.txt'), 'wb') as fp:
            fp.write(test_text)
        content = self._loader.get('mailman:///it/demo.txt')
        self.assertIsInstance(content, str)
        self.assertEqual(content, test_text.decode('utf-8'))
