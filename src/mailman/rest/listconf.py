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

"""Mailing list configuration via REST API."""

__all__ = [
    'ListConfiguration',
    ]


from lazr.config import as_boolean, as_timedelta
from mailman.config import config
from mailman.core.errors import (
    ReadOnlyPATCHRequestError, UnknownPATCHRequestError)
from mailman.interfaces.action import Action
from mailman.interfaces.archiver import ArchivePolicy
from mailman.interfaces.autorespond import ResponseAction
from mailman.interfaces.mailinglist import (
    IAcceptableAliasSet, ReplyToMunging, SubscriptionPolicy)
from mailman.rest.helpers import (
    GetterSetter, bad_request, etag, no_content, not_found, okay)
from mailman.rest.validator import (
    PatchValidator, Validator, enum_validator, list_of_strings_validator)



class AcceptableAliases(GetterSetter):
    """Resource for the acceptable aliases of a mailing list."""

    def get(self, mlist, attribute):
        """Return the mailing list's acceptable aliases."""
        assert attribute == 'acceptable_aliases', (
            'Unexpected attribute: {}'.format(attribute))   # pragma: no cover
        aliases = IAcceptableAliasSet(mlist)
        return sorted(aliases.aliases)

    def put(self, mlist, attribute, value):
        """Change the acceptable aliases.

        Because this is a PUT operation, all previous aliases are cleared
        first.  Thus, this is an overwrite.  The keys in the request are
        ignored.
        """
        assert attribute == 'acceptable_aliases', (
            'Unexpected attribute: {}'.format(attribute))   # pragma: no cover
        alias_set = IAcceptableAliasSet(mlist)
        alias_set.clear()
        for alias in value:
            alias_set.add(alias)



# Additional validators for converting from web request strings to internal
# data types.  See below for details.

def pipeline_validator(pipeline_name):
    """Convert the pipeline name to a string, but only if it's known."""
    if pipeline_name in config.pipelines:
        return pipeline_name
    raise ValueError('Unknown pipeline: {}'.format(pipeline_name))



# This is the list of IMailingList attributes that are exposed through the
# REST API.  The values of the keys are the GetterSetter instance holding the
# decoder used to convert the web request string to an internally valid value.
# The instance also contains the get() and put() methods used to retrieve and
# set the attribute values.  Its .decoder attribute will be None for read-only
# attributes.
#
# The decoder must either return the internal value or raise a ValueError if
# the conversion failed (e.g. trying to turn 'Nope' into a boolean).
#
# Many internal value types can be automatically JSON encoded, but see
# mailman.rest.helpers.ExtendedEncoder for specializations of certain types
# (e.g. datetimes, timedeltas, enums).

ATTRIBUTES = dict(
    acceptable_aliases=AcceptableAliases(list_of_strings_validator),
    admin_immed_notify=GetterSetter(as_boolean),
    admin_notify_mchanges=GetterSetter(as_boolean),
    administrivia=GetterSetter(as_boolean),
    advertised=GetterSetter(as_boolean),
    anonymous_list=GetterSetter(as_boolean),
    autorespond_owner=GetterSetter(enum_validator(ResponseAction)),
    autorespond_postings=GetterSetter(enum_validator(ResponseAction)),
    autorespond_requests=GetterSetter(enum_validator(ResponseAction)),
    autoresponse_grace_period=GetterSetter(as_timedelta),
    autoresponse_owner_text=GetterSetter(str),
    autoresponse_postings_text=GetterSetter(str),
    autoresponse_request_text=GetterSetter(str),
    archive_policy=GetterSetter(enum_validator(ArchivePolicy)),
    bounces_address=GetterSetter(None),
    collapse_alternatives=GetterSetter(as_boolean),
    convert_html_to_plaintext=GetterSetter(as_boolean),
    created_at=GetterSetter(None),
    default_member_action=GetterSetter(enum_validator(Action)),
    default_nonmember_action=GetterSetter(enum_validator(Action)),
    description=GetterSetter(str),
    digest_last_sent_at=GetterSetter(None),
    digest_size_threshold=GetterSetter(float),
    filter_content=GetterSetter(as_boolean),
    first_strip_reply_to=GetterSetter(as_boolean),
    fqdn_listname=GetterSetter(None),
    mail_host=GetterSetter(None),
    allow_list_posts=GetterSetter(as_boolean),
    include_rfc2369_headers=GetterSetter(as_boolean),
    join_address=GetterSetter(None),
    last_post_at=GetterSetter(None),
    leave_address=GetterSetter(None),
    list_name=GetterSetter(None),
    next_digest_number=GetterSetter(None),
    no_reply_address=GetterSetter(None),
    owner_address=GetterSetter(None),
    post_id=GetterSetter(None),
    posting_address=GetterSetter(None),
    posting_pipeline=GetterSetter(pipeline_validator),
    display_name=GetterSetter(str),
    reply_goes_to_list=GetterSetter(enum_validator(ReplyToMunging)),
    reply_to_address=GetterSetter(str),
    request_address=GetterSetter(None),
    scheme=GetterSetter(None),
    send_welcome_message=GetterSetter(as_boolean),
    subject_prefix=GetterSetter(str),
    subscription_policy=GetterSetter(enum_validator(SubscriptionPolicy)),
    volume=GetterSetter(None),
    web_host=GetterSetter(None),
    welcome_message_uri=GetterSetter(str),
    )


VALIDATORS = ATTRIBUTES.copy()
for attribute, gettersetter in list(VALIDATORS.items()):
    if gettersetter.decoder is None:
        del VALIDATORS[attribute]



class ListConfiguration:
    """A mailing list configuration resource."""

    def __init__(self, mailing_list, attribute):
        self._mlist = mailing_list
        self._attribute = attribute

    def on_get(self, request, response):
        """Get a mailing list configuration."""
        resource = {}
        if self._attribute is None:
            # This is a requst for all the mailing list's configuration
            # variables.  Return all readable attributes.
            for attribute in ATTRIBUTES:
                value = ATTRIBUTES[attribute].get(self._mlist, attribute)
                resource[attribute] = value
        elif self._attribute not in ATTRIBUTES:
            # This is a request for a specific, nonexistent attribute.
            not_found(
                response, 'Unknown attribute: {}'.format(self._attribute))
            return
        else:
            # This is a request for a specific attribute.
            attribute = self._attribute
            value = ATTRIBUTES[attribute].get(self._mlist, attribute)
            resource[attribute] = value
        okay(response, etag(resource))

    def on_put(self, request, response):
        """Set a mailing list configuration."""
        attribute = self._attribute
        if attribute is None:
            # This is a request to update all the list's writable
            # configuration variables.  All must be provided in the request.
            validator = Validator(**VALIDATORS)
            try:
                validator.update(self._mlist, request)
            except ValueError as error:
                # Unlike the case where we're PUTting to a specific
                # configuration sub-resource, if we're PUTting to the list's
                # entire configuration, but the request has a bogus attribute,
                # the entire request is considered bad.  We can also get here
                # if one of the attributes is read-only.  The error will
                # contain sufficient details, so just return it as the reason.
                bad_request(response, str(error))
                return
        elif attribute not in ATTRIBUTES:
            # Here we're PUTting to a specific resource, but that attribute is
            # bogus so the URL is considered pointing to a missing resource.
            not_found(response, 'Unknown attribute: {}'.format(attribute))
            return
        elif ATTRIBUTES[attribute].decoder is None:
            bad_request(
                response, 'Read-only attribute: {}'.format(attribute))
            return
        else:
            # We're PUTting to a specific configuration sub-resource.
            validator = Validator(**{attribute: VALIDATORS[attribute]})
            try:
                validator.update(self._mlist, request)
            except ValueError as error:
                bad_request(response, str(error))
                return
        no_content(response)

    def on_patch(self, request, response):
        """Patch the configuration (i.e. partial update)."""
        if self._attribute is None:
            # We're PATCHing one or more of the attributes on the list's
            # configuration resource, so all the writable attributes are valid
            # candidates for updating.
            converters = ATTRIBUTES
        else:
            # We're PATCHing a specific list configuration attribute
            # sub-resource.  Because the request data must be a dictionary, we
            # restrict it to containing only a single key, which must match
            # the attribute name.  First, check for any extra attributes in
            # the request.
            keys = [key for key, value in request.params.items()]
            if len(keys) > 1:
                bad_request(response, 'Expected 1 attribute, got {}'.format(
                    len(keys)))
                return
            converter = ATTRIBUTES.get(self._attribute)
            if converter is None:
                # This is the case where the URL points to a nonexisting list
                # configuration attribute sub-resource.
                not_found(response, 'Unknown attribute: {}'.format(
                    self._attribute))
                return
            converters = {self._attribute: converter}
        try:
            validator = PatchValidator(request, converters)
        except UnknownPATCHRequestError as error:
            # This is the case where the URL points to the list's entire
            # configuration resource, but the request dictionary contains a
            # nonexistent attribute.
            bad_request(
                response, 'Unknown attribute: {}'.format(error.attribute))
            return
        except ReadOnlyPATCHRequestError as error:
            bad_request(
                response, 'Read-only attribute: {}'.format(error.attribute))
            return
        try:
            validator.update(self._mlist, request)
        except ValueError as error:
            bad_request(response, str(error))
        else:
            no_content(response)
