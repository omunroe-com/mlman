# Copyright (C) 2011-2015 by the Free Software Foundation, Inc.
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

"""REST for addresses."""

__all__ = [
    'AllAddresses',
    'AnAddress',
    'UserAddresses',
    ]


from mailman.interfaces.address import (
    ExistingAddressError, InvalidEmailAddressError)
from mailman.interfaces.usermanager import IUserManager
from mailman.rest.helpers import (
    BadRequest, CollectionMixin, NotFound, bad_request, child, created, etag,
    no_content, not_found, okay, path_to)
from mailman.rest.members import MemberCollection
from mailman.rest.preferences import Preferences
from mailman.rest.validator import Validator
from mailman.utilities.datetime import now
from operator import attrgetter
from zope.component import getUtility



class _AddressBase(CollectionMixin):
    """Shared base class for address representations."""

    def _resource_as_dict(self, address):
        """See `CollectionMixin`."""
        # The canonical url for an address is its lower-cased version,
        # although it can be looked up with either its original or lower-cased
        # email address.
        representation = dict(
            email=address.email,
            original_email=address.original_email,
            registered_on=address.registered_on,
            self_link=path_to('addresses/{0}'.format(address.email)),
            )
        # Add optional attributes.  These can be None or the empty string.
        if address.display_name:
            representation['display_name'] = address.display_name
        if address.verified_on:
            representation['verified_on'] = address.verified_on
        if address.user:
            representation['user'] = path_to(
                'users/{0}'.format(address.user.user_id.int))
        return representation

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        return list(getUtility(IUserManager).addresses)



class AllAddresses(_AddressBase):
    """The addresses."""

    def on_get(self, request, response):
        """/addresses"""
        resource = self._make_collection(request)
        okay(response, etag(resource))



class _VerifyResource:
    """A helper resource for verify/unverify POSTS."""

    def __init__(self, address, action):
        self._address = address
        self._action = action
        assert action in ('verify', 'unverify')

    def on_post(self, request, response):
        # We don't care about the POST data, just do the action.
        if self._action == 'verify' and self._address.verified_on is None:
            self._address.verified_on = now()
        elif self._action == 'unverify':
            self._address.verified_on = None
        no_content(response)


class AnAddress(_AddressBase):
    """An address."""

    def __init__(self, email):
        """Get an address by either its original or lower-cased email.

        :param email: The email address of the `IAddress`.
        :type email: string
        """
        self._address = getUtility(IUserManager).get_address(email)

    def on_get(self, request, response):
        """Return a single address."""
        if self._address is None:
            not_found(response)
        else:
            okay(response, self._resource_as_json(self._address))

    def on_delete(self, request, response):
        if self._address is None:
            not_found(response)
        else:
            getUtility(IUserManager).delete_address(self._address)
            no_content(response)

    @child()
    def memberships(self, request, segments):
        """/addresses/<email>/memberships"""
        if len(segments) != 0:
            return BadRequest(), []
        if self._address is None:
            return NotFound(), []
        return AddressMemberships(self._address)

    @child()
    def preferences(self, request, segments):
        """/addresses/<email>/preferences"""
        if len(segments) != 0:
            return NotFound(), []
        if self._address is None:
            return NotFound(), []
        child = Preferences(
            self._address.preferences,
            'addresses/{0}'.format(self._address.email))
        return child, []

    @child()
    def verify(self, request, segments):
        """/addresses/<email>/verify"""
        if len(segments) != 0:
            return BadRequest(), []
        if self._address is None:
            return NotFound(), []
        child = _VerifyResource(self._address, 'verify')
        return child, []

    @child()
    def unverify(self, request, segments):
        """/addresses/<email>/verify"""
        if len(segments) != 0:
            return BadRequest(), []
        if self._address is None:
            return NotFound(), []
        child = _VerifyResource(self._address, 'unverify')
        return child, []

    @child()
    def user(self, request, segments):
        """/addresses/<email>/user"""
        if self._address is None:
            return NotFound(), []
        # Avoid circular imports.
        from mailman.rest.users import AddressUser
        return AddressUser(self._address)



class UserAddresses(_AddressBase):
    """The addresses of a user."""

    def __init__(self, user):
        self._user = user
        super(UserAddresses, self).__init__()

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        return sorted(self._user.addresses,
                      key=attrgetter('original_email'))

    def on_get(self, request, response):
        """/addresses"""
        if self._user is None:
            not_found(response)
        else:
            okay(response, etag(self._make_collection(request)))

    def on_post(self, request, response):
        """POST to /addresses

        Add a new address to the user record.
        """
        if self._user is None:
            not_found(response)
            return
        user_manager = getUtility(IUserManager)
        validator = Validator(email=str,
                              display_name=str,
                              _optional=('display_name',))
        try:
            address = user_manager.create_address(**validator(request))
        except ValueError as error:
            bad_request(response, str(error))
        except InvalidEmailAddressError:
            bad_request(response, b'Invalid email address')
        except ExistingAddressError:
            # Check if the address is not linked to any user, link it to the
            # current user and return it.  Since we're linking to an existing
            # address, ignore any given display_name attribute.
            address = user_manager.get_address(validator(request)['email'])
            if address.user is None:
                address.user = self._user
                location = path_to('addresses/{}'.format(address.email))
                created(response, location)
            else:
                bad_request(response, 'Address belongs to other user.')
        else:
            # Link the address to the current user and return it.
            address.user = self._user
            created(response, path_to('addresses/{}'.format(address.email)))



def membership_key(member):
    # Sort first by mailing list, then by address, then by role.
    return member.list_id, member.address.email, member.role.value


class AddressMemberships(MemberCollection):
    """All the memberships of a particular email address."""

    def __init__(self, address):
        super(AddressMemberships, self).__init__()
        self._address = address

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        # XXX Improve this by implementing a .memberships attribute on
        # IAddress, similar to the way IUser does it.
        #
        # Start by getting the IUser that controls this address.  For now, if
        # the address is not controlled by a user, return the empty set.
        # Later when we address the XXX comment, it will return some
        # memberships.  But really, it should not be legal to subscribe an
        # address to a mailing list that isn't controlled by a user -- maybe!
        user = getUtility(IUserManager).get_user(self._address.email)
        if user is None:
            return []
        return sorted((member for member in user.memberships.members
                       if member.address == self._address),
                      key=membership_key)
