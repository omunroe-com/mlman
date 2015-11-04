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

"""REST for mailing lists."""

__all__ = [
    'AList',
    'AllLists',
    'ListArchivers',
    'ListConfiguration',
    'ListsForDomain',
    'Styles',
    ]


from lazr.config import as_boolean
from mailman.app.lifecycle import create_list, remove_list
from mailman.config import config
from mailman.interfaces.domain import BadDomainSpecificationError
from mailman.interfaces.listmanager import (
    IListManager, ListAlreadyExistsError)
from mailman.interfaces.mailinglist import IListArchiverSet
from mailman.interfaces.member import MemberRole
from mailman.interfaces.styles import IStyleManager
from mailman.interfaces.subscriptions import ISubscriptionService
from mailman.rest.listconf import ListConfiguration
from mailman.rest.helpers import (
    CollectionMixin, GetterSetter, NotFound, bad_request, child, created,
    etag, no_content, not_found, okay, path_to)
from mailman.rest.members import AMember, MemberCollection
from mailman.rest.post_moderation import HeldMessages
from mailman.rest.sub_moderation import SubscriptionRequests
from mailman.rest.validator import Validator
from operator import attrgetter
from zope.component import getUtility



def member_matcher(request, segments):
    """A matcher of member URLs inside mailing lists.

    e.g. /<role>/aperson@example.org
    """
    if len(segments) != 2:
        return None
    try:
        role = MemberRole[segments[0]]
    except KeyError:
        # Not a valid role.
        return None
    return (), dict(role=role, email=segments[1]), ()


def roster_matcher(request, segments):
    """A matcher of all members URLs inside mailing lists.

    e.g. /roster/<role>
    """
    if len(segments) != 2 or segments[0] != 'roster':
        return None
    try:
        return (), dict(role=MemberRole[segments[1]]), ()
    except KeyError:
        # Not a valid role.
        return None


def config_matcher(request, segments):
    """A matcher for a mailing list's configuration resource.

    e.g. /config
    e.g. /config/description
    """
    if len(segments) < 1 or segments[0] != 'config':
        return None
    if len(segments) == 1:
        return (), {}, ()
    if len(segments) == 2:
        return (), dict(attribute=segments[1]), ()
    # More segments are not allowed.
    return None



class _ListBase(CollectionMixin):
    """Shared base class for mailing list representations."""

    def _resource_as_dict(self, mlist):
        """See `CollectionMixin`."""
        return dict(
            display_name=mlist.display_name,
            fqdn_listname=mlist.fqdn_listname,
            list_id=mlist.list_id,
            list_name=mlist.list_name,
            mail_host=mlist.mail_host,
            member_count=mlist.members.member_count,
            volume=mlist.volume,
            self_link=path_to('lists/{0}'.format(mlist.list_id)),
            )

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        return list(getUtility(IListManager))


class AList(_ListBase):
    """A mailing list."""

    def __init__(self, list_identifier):
        # list-id is preferred, but for backward compatibility, fqdn_listname
        # is also accepted.  If the string contains '@', treat it as the
        # latter.
        manager = getUtility(IListManager)
        if '@' in list_identifier:
            self._mlist = manager.get(list_identifier)
        else:
            self._mlist = manager.get_by_list_id(list_identifier)

    def on_get(self, request, response):
        """Return a single mailing list end-point."""
        if self._mlist is None:
            not_found(response)
        else:
            okay(response, self._resource_as_json(self._mlist))

    def on_delete(self, request, response):
        """Delete the named mailing list."""
        if self._mlist is None:
            not_found(response)
        else:
            remove_list(self._mlist)
            no_content(response)

    @child(member_matcher)
    def member(self, request, segments, role, email):
        """Return a single member representation."""
        if self._mlist is None:
            return NotFound(), []
        members = getUtility(ISubscriptionService).find_members(
            email, self._mlist.list_id, role)
        if len(members) == 0:
            return NotFound(), []
        assert len(members) == 1, 'Too many matches'
        return AMember(members[0].member_id)

    @child(roster_matcher)
    def roster(self, request, segments, role):
        """Return the collection of all a mailing list's members."""
        if self._mlist is None:
            return NotFound(), []
        return MembersOfList(self._mlist, role)

    @child(config_matcher)
    def config(self, request, segments, attribute=None):
        """Return a mailing list configuration object."""
        if self._mlist is None:
            return NotFound(), []
        return ListConfiguration(self._mlist, attribute)

    @child()
    def held(self, request, segments):
        """Return a list of held messages for the mailing list."""
        if self._mlist is None:
            return NotFound(), []
        return HeldMessages(self._mlist)

    @child()
    def requests(self, request, segments):
        """Return a list of subscription/unsubscription requests."""
        if self._mlist is None:
            return NotFound(), []
        return SubscriptionRequests(self._mlist)

    @child()
    def archivers(self, request, segments):
        """Return a representation of mailing list archivers."""
        if self._mlist is None:
            return NotFound(), []
        return ListArchivers(self._mlist)



class AllLists(_ListBase):
    """The mailing lists."""

    def on_post(self, request, response):
        """Create a new mailing list."""
        try:
            validator = Validator(fqdn_listname=str,
                                  style_name=str,
                                  _optional=('style_name',))
            mlist = create_list(**validator(request))
        except ListAlreadyExistsError:
            bad_request(response, b'Mailing list exists')
        except BadDomainSpecificationError as error:
            reason = 'Domain does not exist: {}'.format(error.domain)
            bad_request(response, reason.encode('utf-8'))
        except ValueError as error:
            bad_request(response, str(error))
        else:
            created(response, path_to('lists/{0}'.format(mlist.list_id)))

    def on_get(self, request, response):
        """/lists"""
        resource = self._make_collection(request)
        okay(response, etag(resource))



class MembersOfList(MemberCollection):
    """The members of a mailing list."""

    def __init__(self, mailing_list, role):
        super(MembersOfList, self).__init__()
        self._mlist = mailing_list
        self._role = role

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        # Overrides _MemberBase._get_collection() because we only want to
        # return the members from the requested roster.
        roster = self._mlist.get_roster(self._role)
        address_of_member = attrgetter('address.email')
        return list(sorted(roster.members, key=address_of_member))


class ListsForDomain(_ListBase):
    """The mailing lists for a particular domain."""

    def __init__(self, domain):
        self._domain = domain

    def on_get(self, request, response):
        """/domains/<domain>/lists"""
        resource = self._make_collection(request)
        okay(response, etag(resource))

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        return list(self._domain.mailing_lists)



class ArchiverGetterSetter(GetterSetter):
    """Resource for updating archiver statuses."""

    def __init__(self, mlist):
        super(ArchiverGetterSetter, self).__init__()
        self._archiver_set = IListArchiverSet(mlist)

    def put(self, mlist, attribute, value):
        # attribute will contain the (bytes) name of the archiver that is
        # getting a new status.  value will be the representation of the new
        # boolean status.
        archiver = self._archiver_set.get(attribute)
        if archiver is None:
            raise ValueError('No such archiver: {}'.format(attribute))
        archiver.is_enabled = as_boolean(value)


class ListArchivers:
    """The archivers for a list, with their enabled flags."""

    def __init__(self, mlist):
        self._mlist = mlist

    def on_get(self, request, response):
        """Get all the archiver statuses."""
        archiver_set = IListArchiverSet(self._mlist)
        resource = {archiver.name: archiver.is_enabled
                    for archiver in archiver_set.archivers}
        okay(response, etag(resource))

    def patch_put(self, request, response, is_optional):
        archiver_set = IListArchiverSet(self._mlist)
        kws = {archiver.name: ArchiverGetterSetter(self._mlist)
               for archiver in archiver_set.archivers}
        if is_optional:
            # For a PUT, all attributes are optional.
            kws['_optional'] = kws.keys()
        try:
            Validator(**kws).update(self._mlist, request)
        except ValueError as error:
            bad_request(response, str(error))
        else:
            no_content(response)

    def on_put(self, request, response):
        """Update all the archiver statuses."""
        self.patch_put(request, response, is_optional=False)

    def on_patch(self, request, response):
        """Patch some archiver statueses."""
        self.patch_put(request, response, is_optional=True)



class Styles:
    """Simple resource representing all list styles."""

    def __init__(self):
        manager = getUtility(IStyleManager)
        style_names = sorted(style.name for style in manager.styles)
        self._resource = dict(
            style_names=style_names,
            default=config.styles.default)

    def on_get(self, request, response):
        okay(response, etag(self._resource))
