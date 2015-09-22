# Copyright (C) 2012-2015 by the Free Software Foundation, Inc.
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

"""Test the system-wide global configuration."""

__all__ = [
    'TestConfiguration',
    'TestConfigurationErrors',
    'TestExternal',
    ]


import os
import tempfile
import unittest

from contextlib import ExitStack
from mailman.config.config import (
    Configuration, external_configuration, load_external)
from mailman.interfaces.configuration import (
    ConfigurationUpdatedEvent, MissingConfigurationFileError)
from mailman.testing.helpers import configuration, event_subscribers
from mailman.testing.layers import ConfigLayer
from pkg_resources import resource_filename
from unittest import mock



class TestConfiguration(unittest.TestCase):
    layer = ConfigLayer

    def test_push_and_pop_trigger_events(self):
        # Pushing a new configuration onto the stack triggers a
        # post-processing event.
        events = []
        def on_event(event):
            if isinstance(event, ConfigurationUpdatedEvent):
                # Record both the event and the top overlay.
                events.append(event.config.overlays[0].name)
        # Do two pushes, and then pop one of them.
        with event_subscribers(on_event):
            with configuration('test', _configname='first'):
                with configuration('test', _configname='second'):
                    pass
                self.assertEqual(events, ['first', 'second', 'first'])



class TestExternal(unittest.TestCase):
    """Test external configuration file loading APIs."""

    def test_load_external_by_filename(self):
        filename = resource_filename('mailman.config', 'postfix.cfg')
        contents = load_external(filename)
        self.assertEqual(contents[:9], '[postfix]')

    def test_load_external_by_path(self):
        contents = load_external('python:mailman.config.postfix')
        self.assertEqual(contents[:9], '[postfix]')

    def test_external_configuration_by_filename(self):
        filename = resource_filename('mailman.config', 'postfix.cfg')
        parser = external_configuration(filename)
        self.assertEqual(parser.get('postfix', 'postmap_command'),
                         '/usr/sbin/postmap')

    def test_external_configuration_by_path(self):
        parser = external_configuration('python:mailman.config.postfix')
        self.assertEqual(parser.get('postfix', 'postmap_command'),
                         '/usr/sbin/postmap')

    def test_missing_configuration_file(self):
        with self.assertRaises(MissingConfigurationFileError) as cm:
            external_configuration('path:mailman.config.missing')
        self.assertEqual(cm.exception.path, 'path:mailman.config.missing')



class TestConfigurationErrors(unittest.TestCase):
    layer = ConfigLayer

    def test_bad_path_layout_specifier(self):
        # Using a [mailman]layout name that doesn't exist is a fatal error.
        fd, filename = tempfile.mkstemp()
        self.addCleanup(os.remove, filename)
        os.close(fd)
        with open(filename, 'w') as fp:
            print("""\
[mailman]
layout: nonesuch
""", file=fp)
        # Use a fake sys.exit() function that records that it was called, and
        # that prevents further processing.
        config = Configuration()
        # Suppress warning messages in the test output.  Also, make sure that
        # the config.load() call doesn't break global state.
        with ExitStack() as resources:
            resources.enter_context(mock.patch('sys.stderr'))
            resources.enter_context(mock.patch.object(config, '_clear'))
            cm = resources.enter_context(self.assertRaises(SystemExit))
            config.load(filename)
        self.assertEqual(cm.exception.args, (1,))

    def test_path_expansion_infloop(self):
        # A path expansion never completes because it references a non-existent
        # substitution variable.
        fd, filename = tempfile.mkstemp()
        self.addCleanup(os.remove, filename)
        os.close(fd)
        with open(filename, 'w') as fp:
            print("""\
[paths.here]
log_dir: $nopath/log_dir
""", file=fp)
        config = Configuration()
        # Suppress warning messages in the test output.  Also, make sure that
        # the config.load() call doesn't break global state.
        with ExitStack() as resources:
            resources.enter_context(mock.patch('sys.stderr'))
            resources.enter_context(mock.patch.object(config, '_clear'))
            cm = resources.enter_context(self.assertRaises(SystemExit))
            config.load(filename)
        self.assertEqual(cm.exception.args, (1,))
