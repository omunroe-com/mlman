from mailman.interfaces.rules import IRule
from public import public
from zope.interface import implementer


@public
@implementer(IRule)
class AlternateRule:
    name = 'alternate-rule'
    description = 'An alternate rule.'
    record = True

    def check(self, mlist, msg, msgdata):
        return 'alternate' in msgdata
