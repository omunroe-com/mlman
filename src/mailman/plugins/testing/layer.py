# Copyright (C) 2017 by the Free Software Foundation, Inc.
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

"""REST layer for plugins."""

import os

from contextlib import ExitStack
from mailman.testing.helpers import (
    TestableMaster, hackenv, wait_for_webservice)
from mailman.testing.layers import SMTPLayer
from pkg_resources import resource_filename
from public import public


# Don't inherit from RESTLayer since layers get run in bottom up order,
# meaning RESTLayer will get setUp() before this layer does, and that won't
# use the configuration file we need it to use.
@public
class PluginRESTLayer(SMTPLayer):
    @classmethod
    def setUp(cls):
        cls.resources = ExitStack()
        plugin_path = os.path.join(
            os.path.dirname(
                resource_filename('mailman.plugins', '__init__.py')),
            'testing')
        config_file = resource_filename('mailman.plugins.testing', 'rest.cfg')
        cls.resources.enter_context(
            hackenv('MAILMAN_CONFIG_FILE', config_file))
        cls.resources.enter_context(
            hackenv('PYTHONPATH', plugin_path))
        cls.server = TestableMaster(wait_for_webservice)
        cls.server.start('rest')
        cls.resources.callback(cls.server.stop)

    @classmethod
    def tearDown(cls):
        cls.resources.close()
