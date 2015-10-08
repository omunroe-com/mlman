# Copyright (C) 2013-2015 by the Free Software Foundation, Inc.
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

"""nose2 test infrastructure."""

__all__ = [
    'NosePlugin',
    ]


import os
import re
import doctest
import importlib

from mailman.testing.documentation import setup, teardown
from mailman.testing.layers import ConfigLayer, MockAndMonkeyLayer, SMTPLayer
from nose2.events import Plugin
from pkg_resources import resource_filename


DOT = '.'
FLAGS = doctest.ELLIPSIS | doctest.NORMALIZE_WHITESPACE | doctest.REPORT_NDIFF
TOPDIR = os.path.dirname(resource_filename('mailman', '__init__.py'))



class NosePlugin(Plugin):
    configSection = 'mailman'

    def __init__(self):
        super(NosePlugin, self).__init__()
        self.patterns = []
        self.stderr = False
        def set_stderr(ignore):
            self.stderr = True
        self.addArgument(self.patterns, 'P', 'pattern',
                         'Add a test matching pattern')
        self.addFlag(set_stderr, 'E', 'stderr',
                     'Enable stderr logging to sub-runners')

    def startTestRun(self, event):
        MockAndMonkeyLayer.testing_mode = True
        if (    self.stderr or
                len(os.environ.get('MM_VERBOSE_TESTLOG', '').strip()) > 0):
            ConfigLayer.stderr = True

    def getTestCaseNames(self, event):
        if len(self.patterns) == 0:
            # No filter patterns, so everything should be tested.
            return
        # Does the pattern match the fully qualified class name?
        for pattern in self.patterns:
            full_class_name = '{}.{}'.format(
                event.testCase.__module__, event.testCase.__name__)
            if re.search(pattern, full_class_name):
                # Don't suppress this test class.
                return
        names = filter(event.isTestMethod, dir(event.testCase))
        for name in names:
            full_test_name = '{}.{}.{}'.format(
                event.testCase.__module__,
                event.testCase.__name__,
                name)
            for pattern in self.patterns:
                if re.search(pattern, full_test_name):
                    break
            else:
                event.excludedNames.append(name)

    def handleFile(self, event):
        path = event.path[len(TOPDIR)+1:]
        if len(self.patterns) > 0:
            for pattern in self.patterns:
                if re.search(pattern, path):
                    break
            else:
                # Skip this doctest.
                return
        base, ext = os.path.splitext(path)
        if ext != '.rst':
            return
        # Look to see if the package defines a test layer, otherwise use the
        # default layer.  First turn the file system path into a dotted Python
        # module path.
        parent = os.path.dirname(path)
        dotted = 'mailman.' + DOT.join(parent.split(os.path.sep))
        try:
            module = importlib.import_module(dotted)
        except ImportError:
            layer = SMTPLayer
        else:
            layer = getattr(module, 'layer', SMTPLayer)
        test = doctest.DocFileTest(
            path, package='mailman',
            optionflags=FLAGS,
            setUp=setup,
            tearDown=teardown)
        test.layer = layer
        # Suppress the extra "Doctest: ..." line.
        test.shortDescription = lambda: None
        event.extraTests.append(test)

    ## def startTest(self, event):
    ##     import sys; print('vvvvv', event.test, file=sys.stderr)

    ## def stopTest(self, event):
    ##     import sys; print('^^^^^', event.test, file=sys.stderr)
