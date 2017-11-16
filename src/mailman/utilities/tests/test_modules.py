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

"""Tests for mailman.utilities.modules."""

import os
import sys
import unittest

from contextlib import ExitStack, contextmanager
from mailman.interfaces.styles import IStyle
from mailman.utilities.modules import add_components, find_components
from pathlib import Path
from tempfile import TemporaryDirectory


@contextmanager
def hack_syspath(index, path):
    old_path = sys.path[:]
    try:
        sys.path.insert(index, path)
        yield
    finally:
        sys.path = old_path


def clean_mypackage():
    # Make a copy since we'll mutate it as we go.
    for module in sys.modules.copy():
        package, dot, rest = module.partition('.')
        if package == 'mypackage':
            del sys.modules[module]


class TestModuleImports(unittest.TestCase):
    def test_find_modules_with_dotfiles(self):
        # Emacs creates lock files when a single file is opened by more than
        # one user. These files look like .#<filename>.py because of which
        # find_components() tries to import them but fails. All such files
        # should be ignored by default.
        with ExitStack() as resources:
            # Creating a temporary directory and adding it to sys.path.
            temp_package = resources.enter_context(TemporaryDirectory())
            resources.enter_context(hack_syspath(0, temp_package))
            resources.callback(clean_mypackage)
            # Create a module inside the above package along with a good, bad
            # and __init__.py file so that we can import from it.
            module_path = os.path.join(temp_package, 'mypackage')
            os.mkdir(module_path)
            init_file = os.path.join(module_path, '__init__.py')
            Path(init_file).touch()
            good_file = os.path.join(module_path, 'goodfile.py')
            bad_file = os.path.join(module_path, '.#badfile.py')
            with open(good_file, 'w', encoding='utf-8') as fp:
                print("""\
from public import public
from mailman.interfaces.styles import IStyle
from zope.interface import implementer

@public
@implementer(IStyle)
class GoodStyle:
    name = 'good-style'
    def apply(self):
        pass
""", file=fp)
            with open(bad_file, 'w', encoding='utf-8') as fp:
                print("""\
from public import public
from mailman.interfaces.styles import IStyle
from zope.interface import implementer

@public
@implementer(IStyle)
class BadStyle:
    name = 'bad-style'
    def apply(self):
        pass
""", file=fp)
            # Find all the IStyle components in the dummy package.  This
            # should find GoodStyle but not BadStyle.
            names = [component.name
                     for component
                     in find_components('mypackage', IStyle)]
            self.assertEqual(names, ['good-style'])

    def test_find_components_no_instantiate(self):
        # find_components() now instantiates the class unless it's been
        # decorated with the @abstract_component decorator.
        with ExitStack() as resources:
            # Creating a temporary directory and adding it to sys.path.
            temp_package = resources.enter_context(TemporaryDirectory())
            resources.enter_context(hack_syspath(0, temp_package))
            resources.callback(clean_mypackage)
            # Create a module inside the above package along with an
            # __init__.py file so that we can import from it.
            module_path = os.path.join(temp_package, 'mypackage')
            os.mkdir(module_path)
            init_file = os.path.join(module_path, '__init__.py')
            Path(init_file).touch()
            component_file = os.path.join(module_path, 'components.py')
            with open(component_file, 'w', encoding='utf-8') as fp:
                print("""\
from mailman.interfaces.styles import IStyle
from mailman.utilities.modules import abstract_component
from public import public
from zope.interface import implementer

@public
@implementer(IStyle)
class ConcreteStyle:
    name = 'concrete-style'
    def apply(self):
        pass

@public
@implementer(IStyle)
@abstract_component
class AbstractStyle:
    name = 'abstract-style'
    def apply(self):
        pass
""", file=fp)
            names = [component.name
                     for component
                     in find_components('mypackage', IStyle)]
            self.assertEqual(names, ['concrete-style'])

    def test_add_components(self):
        with ExitStack() as resources:
            # Creating a temporary directory and adding it to sys.path.
            temp_package = resources.enter_context(TemporaryDirectory())
            resources.enter_context(hack_syspath(0, temp_package))
            resources.callback(clean_mypackage)
            # Create a module inside the above package along with an
            # __init__.py file so that we can import from it.
            module_path = os.path.join(temp_package, 'mypackage')
            os.mkdir(module_path)
            init_file = os.path.join(module_path, '__init__.py')
            Path(init_file).touch()
            component_file = os.path.join(module_path, 'components.py')
            with open(component_file, 'w', encoding='utf-8') as fp:
                print("""\
from mailman.interfaces.styles import IStyle
from mailman.utilities.modules import abstract_component
from public import public
from zope.interface import implementer

@public
@implementer(IStyle)
class StyleA:
    name = 'styleA'
    def apply(self):
        pass

@public
@implementer(IStyle)
@abstract_component
class StyleB:
    name = 'styleB'
    def apply(self):
        pass

@public
@implementer(IStyle)
class StyleC:
    name = 'styleC'
    def apply(self):
        pass
""", file=fp)
            styles = {}
            add_components('mypackage', IStyle, styles)
            self.assertEqual(set(styles), {'styleA', 'styleC'})

    def test_add_components_duplicates(self):
        # A duplicate name exists, so a RuntimeError is raised.
        with ExitStack() as resources:
            # Creating a temporary directory and adding it to sys.path.
            temp_package = resources.enter_context(TemporaryDirectory())
            resources.enter_context(hack_syspath(0, temp_package))
            resources.callback(clean_mypackage)
            # Create a module inside the above package along with an
            # __init__.py file so that we can import from it.
            module_path = os.path.join(temp_package, 'mypackage')
            os.mkdir(module_path)
            init_file = os.path.join(module_path, '__init__.py')
            Path(init_file).touch()
            component_file = os.path.join(module_path, 'components.py')
            with open(component_file, 'w', encoding='utf-8') as fp:
                print("""\
from mailman.interfaces.styles import IStyle
from mailman.utilities.modules import abstract_component
from public import public
from zope.interface import implementer

@public
@implementer(IStyle)
class StyleA1:
    name = 'styleA'
    def apply(self):
        pass

@public
@implementer(IStyle)
class StyleA2:
    name = 'styleA'
    def apply(self):
        pass
""", file=fp)
            with self.assertRaisesRegex(
                    RuntimeError,
                    'Duplicate key "styleA" found in '
                    '<mypackage.components.StyleA2 object at .*>; '
                    'previously <mypackage.components.StyleA1 object at '
                    '.*>'):
                add_components('mypackage', IStyle, {})
