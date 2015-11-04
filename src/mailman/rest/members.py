# Copyright (C) 2010-2015 by the Free Software Foundation, Inc.
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

"""REST for members."""

__all__ = [
    'AMember',
    'AllMembers',
    'FindMembers',
    'MemberCollection',
    ]


from mailman.app.membership import add_member, delete_member
from mailman.interfaces.address import IAddress, InvalidEmailAddressError
from mailman.interfaces.listmanager import IListManager
from mailman.interfaces.member import (
    AlreadySubscribedError, DeliveryMode, MemberRole, MembershipError,
    MembershipIsBannedError, NotAMemberError)
from mailman.interfaces.registrar import IRegistrar
from mailman.interfaces.subscriptions import (
    ISubscriptionService, RequestRecord, TokenOwner)
from mailman.interfaces.user import IUser, UnverifiedAddressError
from mailman.interfaces.usermanager import IUserManager
from mailman.rest.helpers import (
    CollectionMixin, NotFound, accepted, bad_request, child, conflict,
    created, etag, no_content, not_found, okay, path_to)
from mailman.rest.preferences import Preferences, ReadOnlyPreferences
from mailman.rest.validator import (
    Validator, enum_validator, subscriber_validator)
from operator import attrgetter
from uuid import UUID
from zope.component import getUtility



class _MemberBase(CollectionMixin):
    """Shared base class for member representations."""

    def _resource_as_dict(self, member):
        """See `CollectionMixin`."""
        enum, dot, role = str(member.role).partition('.')
        # The member will always have a member id and an address id.  It will
        # only have a user id if the address is linked to a user.
        # E.g. nonmembers we've only seen via postings to lists they are not
        # subscribed to will not have a user id.   The user_id and the
        # member_id are UUIDs.  We need to use the integer equivalent in the
        # URL.
        member_id = member.member_id.int
        response = dict(
            list_id=member.list_id,
            email=member.address.email,
            role=role,
            address=path_to('addresses/{}'.format(member.address.email)),
            self_link=path_to('members/{}'.format(member_id)),
            delivery_mode=member.delivery_mode,
            member_id=member_id,
            )
        # Add the user link if there is one.
        user = member.user
        if user is not None:
            response['user'] = path_to('users/{}'.format(user.user_id.int))
        return response

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        return list(getUtility(ISubscriptionService))



class MemberCollection(_MemberBase):
    """Abstract class for supporting submemberships.

    This is used for example to return a resource representing all the
    memberships of a mailing list, or all memberships for a specific email
    address.
    """
    def _get_collection(self, request):
        """See `CollectionMixin`."""
        raise NotImplementedError

    def on_get(self, request, response):
        """roster/[members|owners|moderators]"""
        resource = self._make_collection(request)
        okay(response, etag(resource))



class AMember(_MemberBase):
    """A member."""

    def __init__(self, member_id_string):
        # REST gives us the member id as the string of an int; we have to
        # convert it to a UUID.
        try:
            member_id = UUID(int=int(member_id_string))
        except ValueError:
            # The string argument could not be converted to an integer.
            self._member = None
        else:
            service = getUtility(ISubscriptionService)
            self._member = service.get_member(member_id)

    def on_get(self, request, response):
        """Return a single member end-point."""
        if self._member is None:
            not_found(response)
        else:
            okay(response, self._resource_as_json(self._member))

    @child()
    def preferences(self, request, segments):
        """/members/<id>/preferences"""
        if len(segments) != 0:
            return NotFound(), []
        if self._member is None:
            return NotFound(), []
        child = Preferences(
            self._member.preferences,
            'members/{0}'.format(self._member.member_id.int))
        return child, []

    @child()
    def all(self, request, segments):
        """/members/<id>/all/preferences"""
        if len(segments) == 0:
            return NotFound(), []
        if self._member is None:
            return NotFound(), []
        child = ReadOnlyPreferences(
            self._member,
            'members/{0}/all'.format(self._member.member_id.int))
        return child, []

    def on_delete(self, request, response):
        """Delete the member (i.e. unsubscribe)."""
        # Leaving a list is a bit different than deleting a moderator or
        # owner.  Handle the former case first.  For now too, we will not send
        # an admin or user notification.
        if self._member is None:
            not_found(response)
            return
        mlist = getUtility(IListManager).get_by_list_id(self._member.list_id)
        if self._member.role is MemberRole.member:
            try:
                delete_member(mlist, self._member.address.email, False, False)
            except NotAMemberError:
                not_found(response)
                return
        else:
            self._member.unsubscribe()
        no_content(response)

    def on_patch(self, request, response):
        """Patch the membership.

        This is how subscription changes are done.
        """
        if self._member is None:
            not_found(response)
            return
        try:
            values = Validator(
                address=str,
                delivery_mode=enum_validator(DeliveryMode),
                _optional=('address', 'delivery_mode'))(request)
        except ValueError as error:
            bad_request(response, str(error))
            return
        if 'address' in values:
            email = values['address']
            address = getUtility(IUserManager).get_address(email)
            if address is None:
                bad_request(response, b'Address not registered')
                return
            try:
                self._member.address = address
            except (MembershipError, UnverifiedAddressError) as error:
                bad_request(response, str(error))
                return
        if 'delivery_mode' in values:
            self._member.preferences.delivery_mode = values['delivery_mode']
        no_content(response)



class AllMembers(_MemberBase):
    """The members."""

    def on_post(self, request, response):
        """Create a new member."""
        try:
            validator = Validator(
                list_id=str,
                subscriber=subscriber_validator,
                display_name=str,
                delivery_mode=enum_validator(DeliveryMode),
                role=enum_validator(MemberRole),
                pre_verified=bool,
                pre_confirmed=bool,
                pre_approved=bool,
                _optional=('delivery_mode', 'display_name', 'role',
                           'pre_verified', 'pre_confirmed', 'pre_approved'))
            arguments = validator(request)
        except ValueError as error:
            bad_request(response, str(error))
            return
        # Dig the mailing list out of the arguments.
        list_id = arguments.pop('list_id')
        mlist = getUtility(IListManager).get_by_list_id(list_id)
        if mlist is None:
            bad_request(response, b'No such list')
            return
        # Figure out what kind of subscriber is being registered.  Either it's
        # a user via their preferred email address or it's an explicit address.
        # If it's a UUID, then it must be associated with an existing user.
        subscriber = arguments.pop('subscriber')
        user_manager = getUtility(IUserManager)
        # We use the display name if there is one.
        display_name = arguments.pop('display_name', '')
        if isinstance(subscriber, UUID):
            user = user_manager.get_user_by_id(subscriber)
            if user is None:
                bad_request(response, b'No such user')
                return
            subscriber = user
        else:
            # This must be an email address.  See if there's an existing
            # address object associated with this email.
            address = user_manager.get_address(subscriber)
            if address is None:
                # Create a new address, which of course will not be validated.
                address = user_manager.create_address(
                    subscriber, display_name)
            subscriber = address
        # What role are we subscribing?  Regular members go through the
        # subscription policy workflow while owners, moderators, and
        # nonmembers go through the legacy API for now.
        role = arguments.pop('role', MemberRole.member)
        if role is MemberRole.member:
            # Get the pre_ flags for the subscription workflow.
            pre_verified = arguments.pop('pre_verified', False)
            pre_confirmed = arguments.pop('pre_confirmed', False)
            pre_approved = arguments.pop('pre_approved', False)
            # Now we can run the registration process until either the
            # subscriber is subscribed, or the workflow is paused for
            # verification, confirmation, or approval.
            registrar = IRegistrar(mlist)
            try:
                token, token_owner, member = registrar.register(
                    subscriber,
                    pre_verified=pre_verified,
                    pre_confirmed=pre_confirmed,
                    pre_approved=pre_approved)
            except AlreadySubscribedError:
                conflict(response, b'Member already subscribed')
                return
            if token is None:
                assert token_owner is TokenOwner.no_one, token_owner
                # The subscription completed.  Let's get the resulting member
                # and return the location to the new member.  Member ids are
                # UUIDs and need to be converted to URLs because JSON doesn't
                # directly support UUIDs.
                member_id = member.member_id.int
                location = path_to('members/{0}'.format(member_id))
                created(response, location)
                return
            # The member could not be directly subscribed because there are
            # some out-of-band steps that need to be completed.  E.g. the user
            # must confirm their subscription or the moderator must approve
            # it.  In this case, an HTTP 202 Accepted is exactly the code that
            # we should use, and we'll return both the confirmation token and
            # the "token owner" so the client knows who should confirm it.
            assert token is not None, token
            assert token_owner is not TokenOwner.no_one, token_owner
            assert member is None, member
            content = dict(token=token, token_owner=token_owner.name)
            accepted(response, etag(content))
            return
        # 2015-04-15 BAW: We're subscribing some role other than a regular
        # member.  Use the legacy API for this for now.
        assert role in (MemberRole.owner,
                        MemberRole.moderator,
                        MemberRole.nonmember)
        # 2015-04-15 BAW: We're limited to using an email address with this
        # legacy API, so if the subscriber is a user, the user must have a
        # preferred address, which we'll use, even though it will subscribe
        # the explicit address.  It is an error if the user does not have a
        # preferred address.
        #
        # If the subscriber is an address object, just use that.
        if IUser.providedBy(subscriber):
            if subscriber.preferred_address is None:
                bad_request(response, b'User without preferred address')
                return
            email = subscriber.preferred_address.email
        else:
            assert IAddress.providedBy(subscriber)
            email = subscriber.email
        delivery_mode = arguments.pop('delivery_mode', DeliveryMode.regular)
        record = RequestRecord(email, display_name, delivery_mode)
        try:
            member = add_member(mlist, record, role)
        except InvalidEmailAddressError:
            bad_request(response, b'Invalid email address')
            return
        except MembershipIsBannedError:
            bad_request(response, b'Membership is banned')
            return
        # The subscription completed.  Let's get the resulting member
        # and return the location to the new member.  Member ids are
        # UUIDs and need to be converted to URLs because JSON doesn't
        # directly support UUIDs.
        member_id = member.member_id.int
        location = path_to('members/{0}'.format(member_id))
        created(response, location)
        return

    def on_get(self, request, response):
        """/members"""
        resource = self._make_collection(request)
        okay(response, etag(resource))



class _FoundMembers(MemberCollection):
    """The found members collection."""

    def __init__(self, members):
        super(_FoundMembers, self).__init__()
        self._members = members

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        address_of_member = attrgetter('address.email')
        return list(sorted(self._members, key=address_of_member))


class FindMembers(_MemberBase):
    """/members/find"""

    def on_post(self, request, response):
        """Find a member"""
        service = getUtility(ISubscriptionService)
        validator = Validator(
            list_id=str,
            subscriber=str,
            role=enum_validator(MemberRole),
            _optional=('list_id', 'subscriber', 'role'))
        try:
            members = service.find_members(**validator(request))
        except ValueError as error:
            bad_request(response, str(error))
        else:
            resource = _FoundMembers(members)._make_collection(request)
            okay(response, etag(resource))
