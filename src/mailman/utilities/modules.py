# Copyright (C) 2009-2016 by the Free Software Foundation, Inc.
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

"""Package and module utilities."""

__all__ = [
    'call_name',
    'expand_path',
    'find_components',
    'find_name',
    'scan_module',
    ]


import os
import sys

from pkg_resources import resource_filename, resource_listdir



def find_name(dotted_name):
    """Import and return the named object in package space.

    :param dotted_name: The dotted module path name to the object.
    :type dotted_name: string
    :return: The object.
    :rtype: object
    """
    package_path, dot, object_name = dotted_name.rpartition('.')
    __import__(package_path)
    return getattr(sys.modules[package_path], object_name)



def call_name(dotted_name, *args, **kws):
    """Imports and calls the named object in package space.

    :param dotted_name: The dotted module path name to the object.
    :type dotted_name: string
    :param args: The positional arguments.
    :type args: tuple
    :param kws: The keyword arguments.
    :type kws: dict
    :return: The object.
    :rtype: object
    """
    named_callable = find_name(dotted_name)
    return named_callable(*args, **kws)



def scan_module(module, interface):
    """Return all the items in a module that conform to an interface.

    :param module: A module object.  The module's `__all__` will be scanned.
    :type module: module
    :param interface: The interface that returned objects must conform to.
    :type interface: `Interface`
    :return: The sequence of matching components.
    :rtype: objects implementing `interface`
    """
    missing = object()
    for name in module.__all__:
        component = getattr(module, name, missing)
        assert component is not missing, (
            '%s has bad __all__: %s' % (module, name))
        if interface.implementedBy(component):
            yield component



def find_components(package, interface):
    """Find components which conform to a given interface.

    Search all the modules in a given package, returning an iterator over all
    objects found that conform to the given interface.

    :param package: The package path to search.
    :type package: string
    :param interface: The interface that returned objects must conform to.
    :type interface: `Interface`
    :return: The sequence of matching components.
    :rtype: objects implementing `interface`
    """
    for filename in resource_listdir(package, ''):
        basename, extension = os.path.splitext(filename)
        if extension != '.py':
            continue
        module_name = '{0}.{1}'.format(package, basename)
        __import__(module_name, fromlist='*')
        module = sys.modules[module_name]
        if not hasattr(module, '__all__'):
            continue
        for component in scan_module(module, interface):
            yield component



def expand_path(url):
    """Expand a python: path, returning the absolute file system path."""
    # Is the context coming from a file system or Python path?
    if url.startswith('python:'):
        resource_path = url[7:]
        package, dot, resource = resource_path.rpartition('.')
        return resource_filename(package, resource + '.cfg')
    else:
        return url
