import os

from mailman.interfaces.plugin import IPlugin
from public import public
from zope.interface import implementer


@public
@implementer(IPlugin)
class ExamplePlugin:
    def pre_hook(self):
        if os.environ.get('DEBUG_HOOKS'):
            print("I'm in my pre-hook")

    def post_hook(self):
        if os.environ.get('DEBUG_HOOKS'):
            print("I'm in my post-hook")

    @property
    def resource(self):
        return None
