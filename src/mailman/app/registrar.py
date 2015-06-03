# Copyright (C) 2007-2015 by the Free Software Foundation, Inc.
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

"""Implementation of the IRegistrar interface."""

__all__ = [
    'Registrar',
    'handle_ConfirmationNeededEvent',
    ]


import logging

from mailman.app.subscriptions import SubscriptionWorkflow
from mailman.core.i18n import _
from mailman.database.transaction import flush
from mailman.email.message import UserNotification
from mailman.interfaces.pending import IPendable, IPendings
from mailman.interfaces.registrar import ConfirmationNeededEvent, IRegistrar
from mailman.interfaces.templates import ITemplateLoader
from mailman.interfaces.workflow import IWorkflowStateManager
from zope.component import getUtility
from zope.interface import implementer


log = logging.getLogger('mailman.error')



@implementer(IPendable)
class PendableRegistration(dict):
    PEND_KEY = 'registration'



@implementer(IRegistrar)
class Registrar:
    """Handle registrations and confirmations for subscriptions."""

    def __init__(self, mlist):
        self._mlist = mlist

    def register(self, subscriber=None, *,
                 pre_verified=False, pre_confirmed=False, pre_approved=False):
        """See `IRegistrar`."""
        workflow = SubscriptionWorkflow(
            self._mlist, subscriber,
            pre_verified=pre_verified,
            pre_confirmed=pre_confirmed,
            pre_approved=pre_approved)
        list(workflow)
        return workflow.token, workflow.token_owner, workflow.member

    def confirm(self, token):
        """See `IRegistrar`."""
        workflow = SubscriptionWorkflow(self._mlist)
        workflow.token = token
        workflow.restore()
        list(workflow)
        return workflow.token, workflow.token_owner, workflow.member

    def discard(self, token):
        """See `IRegistrar`."""
        with flush():
            getUtility(IPendings).confirm(token)
            getUtility(IWorkflowStateManager).discard(
                SubscriptionWorkflow.__name__, token)



def handle_ConfirmationNeededEvent(event):
    if not isinstance(event, ConfirmationNeededEvent):
        return
    # There are three ways for a user to confirm their subscription.  They
    # can reply to the original message and let the VERP'd return address
    # encode the token, they can reply to the robot and keep the token in
    # the Subject header, or they can click on the URL in the body of the
    # message and confirm through the web.
    subject = 'confirm ' + event.token
    confirm_address = event.mlist.confirm_address(event.token)
    # For i18n interpolation.
    confirm_url = event.mlist.domain.confirm_url(event.token)
    email_address = event.email
    domain_name = event.mlist.domain.mail_host
    contact_address = event.mlist.owner_address
    # Send a verification email to the address.
    template = getUtility(ITemplateLoader).get(
        'mailman:///{0}/{1}/confirm.txt'.format(
            event.mlist.fqdn_listname,
            event.mlist.preferred_language.code))
    text = _(template)
    msg = UserNotification(email_address, confirm_address, subject, text)
    msg.send(event.mlist, add_precedence=False)
