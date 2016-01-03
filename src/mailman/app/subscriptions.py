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

"""Handle subscriptions."""

__all__ = [
    'SubscriptionService',
    'SubscriptionWorkflow',
    'handle_ListDeletingEvent',
    ]


import uuid
import logging

from email.utils import formataddr
from enum import Enum
from datetime import timedelta
from mailman.app.membership import delete_member
from mailman.app.workflow import Workflow
from mailman.core.i18n import _
from mailman.database.transaction import dbconnection
from mailman.email.message import UserNotification
from mailman.interfaces.address import IAddress
from mailman.interfaces.bans import IBanManager
from mailman.interfaces.listmanager import (
    IListManager, ListDeletingEvent, NoSuchListError)
from mailman.interfaces.mailinglist import SubscriptionPolicy
from mailman.interfaces.member import MembershipIsBannedError
from mailman.interfaces.pending import IPendable, IPendings
from mailman.interfaces.registrar import ConfirmationNeededEvent
from mailman.interfaces.subscriptions import ISubscriptionService, TokenOwner
from mailman.interfaces.user import IUser
from mailman.interfaces.usermanager import IUserManager
from mailman.interfaces.workflow import IWorkflowStateManager
from mailman.model.member import Member
from mailman.utilities.datetime import now
from mailman.utilities.i18n import make
from operator import attrgetter
from sqlalchemy import and_, or_
from zope.component import getUtility
from zope.event import notify
from zope.interface import implementer


log = logging.getLogger('mailman.subscribe')



def _membership_sort_key(member):
    """Sort function for find_members().

    The members are sorted first by unique list id, then by subscribed email
    address, then by role.
    """
    return (member.list_id, member.address.email, member.role.value)


class WhichSubscriber(Enum):
    address = 1
    user = 2


@implementer(IPendable)
class Pendable(dict):
    pass



class SubscriptionWorkflow(Workflow):
    """Workflow of a subscription request."""

    INITIAL_STATE = 'sanity_checks'
    SAVE_ATTRIBUTES = (
        'pre_approved',
        'pre_confirmed',
        'pre_verified',
        'address_key',
        'subscriber_key',
        'user_key',
        'token_owner_key',
        )

    def __init__(self, mlist, subscriber=None, *,
                 pre_verified=False, pre_confirmed=False, pre_approved=False):
        super().__init__()
        self.mlist = mlist
        self.address = None
        self.user = None
        self.which = None
        self.member = None
        self._set_token(TokenOwner.no_one)
        # The subscriber must be either an IUser or IAddress.
        if IAddress.providedBy(subscriber):
            self.address = subscriber
            self.user = self.address.user
            self.which = WhichSubscriber.address
        elif IUser.providedBy(subscriber):
            self.address = subscriber.preferred_address
            self.user = subscriber
            self.which = WhichSubscriber.user
        self.subscriber = subscriber
        self.pre_verified = pre_verified
        self.pre_confirmed = pre_confirmed
        self.pre_approved = pre_approved

    @property
    def user_key(self):
        # For save.
        return self.user.user_id.hex

    @user_key.setter
    def user_key(self, hex_key):
        # For restore.
        uid = uuid.UUID(hex_key)
        self.user = getUtility(IUserManager).get_user_by_id(uid)
        assert self.user is not None

    @property
    def address_key(self):
        # For save.
        return self.address.email

    @address_key.setter
    def address_key(self, email):
        # For restore.
        self.address = getUtility(IUserManager).get_address(email)
        assert self.address is not None

    @property
    def subscriber_key(self):
        return self.which.value

    @subscriber_key.setter
    def subscriber_key(self, key):
        self.which = WhichSubscriber(key)

    @property
    def token_owner_key(self):
        return self.token_owner.value

    @token_owner_key.setter
    def token_owner_key(self, value):
        self.token_owner = TokenOwner(value)

    def _set_token(self, token_owner):
        assert isinstance(token_owner, TokenOwner)
        pendings = getUtility(IPendings)
        # Clear out the previous pending token if there is one.
        if self.token is not None:
            pendings.confirm(self.token)
        # Create a new token to prevent replay attacks.  It seems like this
        # would produce the same token, but it won't because the pending adds a
        # bit of randomization.
        self.token_owner = token_owner
        if token_owner is TokenOwner.no_one:
            self.token = None
            return
        pendable = Pendable(
            list_id=self.mlist.list_id,
            email=self.address.email,
            display_name=self.address.display_name,
            when=now().replace(microsecond=0).isoformat(),
            token_owner=token_owner.name,
            )
        self.token = pendings.add(pendable, timedelta(days=3650))

    def _step_sanity_checks(self):
        # Ensure that we have both an address and a user, even if the address
        # is not verified.  We can't set the preferred address until it is
        # verified.
        if self.user is None:
            # The address has no linked user so create one, link it, and set
            # the user's preferred address.
            assert self.address is not None, 'No address or user'
            self.user = getUtility(IUserManager).make_user(self.address.email)
        if self.address is None:
            assert self.user.preferred_address is None, (
                "Preferred address exists, but wasn't used in constructor")
            addresses = list(self.user.addresses)
            if len(addresses) == 0:
                raise AssertionError('User has no addresses: {}'.format(
                    self.user))
            # This is rather arbitrary, but we have no choice.
            self.address = addresses[0]
        assert self.user is not None and self.address is not None, (
            'Insane sanity check results')
        # Is this email address banned?
        if IBanManager(self.mlist).is_banned(self.address.email):
            raise MembershipIsBannedError(self.mlist, self.address.email)
        # Start out with the subscriber being the token owner.
        self.push('verification_checks')

    def _step_verification_checks(self):
        # Is the address already verified, or is the pre-verified flag set?
        if self.address.verified_on is None:
            if self.pre_verified:
                self.address.verified_on = now()
            else:
                # The address being subscribed is not yet verified, so we need
                # to send a validation email that will also confirm that the
                # user wants to be subscribed to this mailing list.
                self.push('send_confirmation')
                return
        self.push('confirmation_checks')

    def _step_confirmation_checks(self):
        # If the list's subscription policy is open, then the user can be
        # subscribed right here and now.
        if self.mlist.subscription_policy is SubscriptionPolicy.open:
            self.push('do_subscription')
            return
        # If we do not need the user's confirmation, then skip to the
        # moderation checks.
        if self.mlist.subscription_policy is SubscriptionPolicy.moderate:
            self.push('moderation_checks')
            return
        # If the subscription has been pre-confirmed, then we can skip the
        # confirmation check can be skipped.  If moderator approval is
        # required we need to check that, otherwise we can go straight to
        # subscription.
        if self.pre_confirmed:
            next_step = ('moderation_checks'
                         if self.mlist.subscription_policy is
                            SubscriptionPolicy.confirm_then_moderate
                         else 'do_subscription')
            self.push(next_step)
            return
        # The user must confirm their subscription.
        self.push('send_confirmation')

    def _step_moderation_checks(self):
        # Does the moderator need to approve the subscription request?
        assert self.mlist.subscription_policy in (
            SubscriptionPolicy.moderate,
            SubscriptionPolicy.confirm_then_moderate,
            ), self.mlist.subscription_policy
        if self.pre_approved:
            self.push('do_subscription')
        else:
            self.push('get_moderator_approval')

    def _step_get_moderator_approval(self):
        # Here's the next step in the workflow, assuming the moderator
        # approves of the subscription.  If they don't, the workflow and
        # subscription request will just be thrown away.
        self._set_token(TokenOwner.moderator)
        self.push('subscribe_from_restored')
        self.save()
        log.info('{}: held subscription request from {}'.format(
            self.mlist.fqdn_listname, self.address.email))
        # Possibly send a notification to the list moderators.
        if self.mlist.admin_immed_notify:
            subject = _(
                'New subscription request to $self.mlist.display_name '
                'from $self.address.email')
            username = formataddr(
                (self.subscriber.display_name, self.address.email))
            text = make('subauth.txt',
                        mailing_list=self.mlist,
                        username=username,
                        listname=self.mlist.fqdn_listname,
                        )
            # This message should appear to come from the <list>-owner so as
            # to avoid any useless bounce processing.
            msg = UserNotification(
                self.mlist.owner_address, self.mlist.owner_address,
                subject, text, self.mlist.preferred_language)
            msg.send(self.mlist, tomoderators=True)
        # The workflow must stop running here.
        raise StopIteration

    def _step_subscribe_from_restored(self):
        # Prevent replay attacks.
        self._set_token(TokenOwner.no_one)
        # Restore a little extra state that can't be stored in the database
        # (because the order of setattr() on restore is indeterminate), then
        # subscribe the user.
        if self.which is WhichSubscriber.address:
            self.subscriber = self.address
        else:
            assert self.which is WhichSubscriber.user
            self.subscriber = self.user
        self.push('do_subscription')

    def _step_do_subscription(self):
        # We can immediately subscribe the user to the mailing list.
        self.member = self.mlist.subscribe(self.subscriber)
        # This workflow is done so throw away any associated state.
        getUtility(IWorkflowStateManager).restore(self.name, self.token)

    def _step_send_confirmation(self):
        self._set_token(TokenOwner.subscriber)
        self.push('do_confirm_verify')
        self.save()
        # Triggering this event causes the confirmation message to be sent.
        notify(ConfirmationNeededEvent(
            self.mlist, self.token, self.address.email))
        # Now we wait for the confirmation.
        raise StopIteration

    def _step_do_confirm_verify(self):
        # Restore a little extra state that can't be stored in the database
        # (because the order of setattr() on restore is indeterminate), then
        # continue with the confirmation/verification step.
        if self.which is WhichSubscriber.address:
            self.subscriber = self.address
        else:
            assert self.which is WhichSubscriber.user
            self.subscriber = self.user
        # Reset the token so it can't be used in a replay attack.
        self._set_token(TokenOwner.no_one)
        # The user has confirmed their subscription request, and also verified
        # their email address if necessary.  This latter needs to be set on the
        # IAddress, but there's nothing more to do about the confirmation step.
        # We just continue along with the workflow.
        if self.address.verified_on is None:
            self.address.verified_on = now()
        # The next step depends on the mailing list's subscription policy.
        next_step = ('moderation_checks'
                     if self.mlist.subscription_policy in (
                         SubscriptionPolicy.moderate,
                         SubscriptionPolicy.confirm_then_moderate,
                         )
                    else 'do_subscription')
        self.push(next_step)



@implementer(ISubscriptionService)
class SubscriptionService:
    """Subscription services for the REST API."""

    __name__ = 'members'

    def get_members(self):
        """See `ISubscriptionService`."""
        # {list_id -> {role -> [members]}}
        by_list = {}
        user_manager = getUtility(IUserManager)
        for member in user_manager.members:
            by_role = by_list.setdefault(member.list_id, {})
            members = by_role.setdefault(member.role.name, [])
            members.append(member)
        # Flatten into single list sorted as per the interface.
        all_members = []
        address_of_member = attrgetter('address.email')
        for list_id in sorted(by_list):
            by_role = by_list[list_id]
            all_members.extend(
                sorted(by_role.get('owner', []), key=address_of_member))
            all_members.extend(
                sorted(by_role.get('moderator', []), key=address_of_member))
            all_members.extend(
                sorted(by_role.get('member', []), key=address_of_member))
        return all_members

    @dbconnection
    def get_member(self, store, member_id):
        """See `ISubscriptionService`."""
        members = store.query(Member).filter(Member._member_id == member_id)
        if members.count() == 0:
            return None
        else:
            assert members.count() == 1, 'Too many matching members'
            return members[0]

    @dbconnection
    def find_members(self, store, subscriber=None, list_id=None, role=None):
        """See `ISubscriptionService`."""
        # If `subscriber` is a user id, then we'll search for all addresses
        # which are controlled by the user, otherwise we'll just search for
        # the given address.
        user_manager = getUtility(IUserManager)
        if subscriber is None and list_id is None and role is None:
            return []
        # Querying for the subscriber is the most complicated part, because
        # the parameter can either be an email address or a user id.
        query = []
        if subscriber is not None:
            if isinstance(subscriber, str):
                # subscriber is an email address.
                address = user_manager.get_address(subscriber)
                user = user_manager.get_user(subscriber)
                # This probably could be made more efficient.
                if address is None or user is None:
                    return []
                query.append(or_(Member.address_id == address.id,
                                 Member.user_id == user.id))
            else:
                # subscriber is a user id.
                user = user_manager.get_user_by_id(subscriber)
                address_ids = list(address.id for address in user.addresses
                                   if address.id is not None)
                if len(address_ids) == 0 or user is None:
                    return []
                query.append(or_(Member.user_id == user.id,
                                 Member.address_id.in_(address_ids)))
        # Calculate the rest of the query expression, which will get And'd
        # with the Or clause above (if there is one).
        if list_id is not None:
            query.append(Member.list_id == list_id)
        if role is not None:
            query.append(Member.role == role)
        results = store.query(Member).filter(and_(*query))
        return sorted(results, key=_membership_sort_key)

    def __iter__(self):
        for member in self.get_members():
            yield member

    def leave(self, list_id, email):
        """See `ISubscriptionService`."""
        mlist = getUtility(IListManager).get_by_list_id(list_id)
        if mlist is None:
            raise NoSuchListError(list_id)
        # XXX for now, no notification or user acknowledgment.
        delete_member(mlist, email, False, False)



def handle_ListDeletingEvent(event):
    """Delete a mailing list's members when the list is being deleted."""

    if not isinstance(event, ListDeletingEvent):
        return
    # Find all the members still associated with the mailing list.
    members = getUtility(ISubscriptionService).find_members(
        list_id=event.mailing_list.list_id)
    for member in members:
        member.unsubscribe()
