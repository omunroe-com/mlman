# Copyright (C) 2010-2016 by the Free Software Foundation, Inc.
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

"""REST for domains."""

__all__ = [
    'ADomain',
    'AllDomains',
    ]


from mailman.interfaces.domain import (
    BadDomainSpecificationError, IDomainManager)
from mailman.rest.helpers import (
    BadRequest, CollectionMixin, NotFound, bad_request, child, created, etag,
    no_content, not_found, okay, path_to)
from mailman.rest.lists import ListsForDomain
from mailman.rest.users import OwnersForDomain
from mailman.rest.validator import Validator, list_of_strings_validator
from zope.component import getUtility



class _DomainBase(CollectionMixin):
    """Shared base class for domain representations."""

    def _resource_as_dict(self, domain):
        """See `CollectionMixin`."""
        return dict(
            base_url=domain.base_url,
            description=domain.description,
            mail_host=domain.mail_host,
            self_link=path_to('domains/{0}'.format(domain.mail_host)),
            url_host=domain.url_host,
            )

    def _get_collection(self, request):
        """See `CollectionMixin`."""
        return list(getUtility(IDomainManager))


class ADomain(_DomainBase):
    """A domain."""

    def __init__(self, domain):
        self._domain = domain

    def on_get(self, request, response):
        """Return a single domain end-point."""
        domain = getUtility(IDomainManager).get(self._domain)
        if domain is None:
            not_found(response)
        else:
            okay(response, self._resource_as_json(domain))

    def on_delete(self, request, response):
        """Delete the domain."""
        try:
            getUtility(IDomainManager).remove(self._domain)
        except KeyError:
            # The domain does not exist.
            not_found(response)
        else:
            no_content(response)

    @child()
    def lists(self, request, segments):
        """/domains/<domain>/lists"""
        if len(segments) == 0:
            domain = getUtility(IDomainManager).get(self._domain)
            if domain is None:
                return NotFound()
            return ListsForDomain(domain)
        else:
            return BadRequest(), []

    @child()
    def owners(self, request, segments):
        """/domains/<domain>/owners"""
        if len(segments) == 0:
            domain = getUtility(IDomainManager).get(self._domain)
            if domain is None:
                return NotFound()
            return OwnersForDomain(domain)
        else:
            return BadRequest(), []


class AllDomains(_DomainBase):
    """The domains."""

    def on_post(self, request, response):
        """Create a new domain."""
        domain_manager = getUtility(IDomainManager)
        try:
            validator = Validator(mail_host=str,
                                  description=str,
                                  base_url=str,
                                  owner=list_of_strings_validator,
                                  _optional=(
                                      'description', 'base_url', 'owner'))
            values = validator(request)
            # For consistency, owners are passed in as multiple `owner` keys,
            # but .add() requires an `owners` keyword.  Match impedence.
            owners = values.pop('owner', None)
            if owners is not None:
                values['owners'] = owners
            domain = domain_manager.add(**values)
        except BadDomainSpecificationError as error:
            bad_request(response, str(error))
        except ValueError as error:
            bad_request(response, str(error))
        else:
            created(response, path_to('domains/{0}'.format(domain.mail_host)))

    def on_get(self, request, response):
        """/domains"""
        resource = self._make_collection(request)
        okay(response, etag(resource))
