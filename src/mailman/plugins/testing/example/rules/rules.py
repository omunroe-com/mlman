from mailman.interfaces.rules import IRule
from public import public
from zope.interface import implementer


@public
@implementer(IRule)
class ExampleRule:
    name = 'example-rule'
    description = 'An example rule.'
    record = True

    def check(self, mlist, msg, msgdata):
        return 'example' in msgdata
