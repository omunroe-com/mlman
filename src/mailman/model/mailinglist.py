# Copyright (C) 2006-2016 by the Free Software Foundation, Inc.
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

"""Model for mailing lists."""

__all__ = [
    'MailingList',
    ]


import os

from mailman.config import config
from mailman.database.model import Model
from mailman.database.transaction import dbconnection
from mailman.database.types import Enum
from mailman.interfaces.action import Action, FilterAction
from mailman.interfaces.address import IAddress
from mailman.interfaces.archiver import ArchivePolicy
from mailman.interfaces.autorespond import ResponseAction
from mailman.interfaces.bounce import UnrecognizedBounceDisposition
from mailman.interfaces.digests import DigestFrequency
from mailman.interfaces.domain import IDomainManager
from mailman.interfaces.languages import ILanguageManager
from mailman.interfaces.mailinglist import (
    IAcceptableAlias, IAcceptableAliasSet, IListArchiver, IListArchiverSet,
    IMailingList, Personalization, ReplyToMunging, SubscriptionPolicy)
from mailman.interfaces.member import (
    AlreadySubscribedError, MemberRole, MissingPreferredAddressError,
    SubscriptionEvent)
from mailman.interfaces.mime import FilterType
from mailman.interfaces.nntp import NewsgroupModeration
from mailman.interfaces.user import IUser
from mailman.model import roster
from mailman.model.digests import OneLastDigest
from mailman.model.member import Member
from mailman.model.mime import ContentFilter
from mailman.model.preferences import Preferences
from mailman.utilities.filesystem import makedirs
from mailman.utilities.string import expand
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, Interval,
    LargeBinary, PickleType, Unicode)
from sqlalchemy.event import listen
from sqlalchemy.orm import relationship
from urllib.parse import urljoin
from zope.component import getUtility
from zope.event import notify
from zope.interface import implementer


SPACE = ' '
UNDERSCORE = '_'



@implementer(IMailingList)
class MailingList(Model):
    """See `IMailingList`."""

    __tablename__ = 'mailinglist'

    id = Column(Integer, primary_key=True)

    # XXX denotes attributes that should be part of the public interface but
    # are currently missing.

    # List identity
    list_name = Column(Unicode)
    mail_host = Column(Unicode)
    _list_id = Column('list_id', Unicode)
    allow_list_posts = Column(Boolean)
    include_rfc2369_headers = Column(Boolean)
    advertised = Column(Boolean)
    anonymous_list = Column(Boolean)
    # Attributes not directly modifiable via the web u/i
    created_at = Column(DateTime)
    # Attributes which are directly modifiable via the web u/i.  The more
    # complicated attributes are currently stored as pickles, though that
    # will change as the schema and implementation is developed.
    next_request_id = Column(Integer)
    next_digest_number = Column(Integer)
    digest_last_sent_at = Column(DateTime)
    volume = Column(Integer)
    last_post_at = Column(DateTime)
    # Attributes which are directly modifiable via the web u/i.  The more
    # complicated attributes are currently stored as pickles, though that
    # will change as the schema and implementation is developed.
    accept_these_nonmembers = Column(PickleType) # XXX
    admin_immed_notify = Column(Boolean)
    admin_notify_mchanges = Column(Boolean)
    administrivia = Column(Boolean)
    archive_policy = Column(Enum(ArchivePolicy))
    # Automatic responses.
    autoresponse_grace_period = Column(Interval)
    autorespond_owner = Column(Enum(ResponseAction))
    autoresponse_owner_text = Column(Unicode)
    autorespond_postings = Column(Enum(ResponseAction))
    autoresponse_postings_text = Column(Unicode)
    autorespond_requests = Column(Enum(ResponseAction))
    autoresponse_request_text = Column(Unicode)
    # Content filters.
    filter_action = Column(Enum(FilterAction))
    filter_content = Column(Boolean)
    collapse_alternatives = Column(Boolean)
    convert_html_to_plaintext = Column(Boolean)
    # Bounces.
    bounce_info_stale_after = Column(Interval) # XXX
    bounce_matching_headers = Column(Unicode) # XXX
    bounce_notify_owner_on_disable = Column(Boolean) # XXX
    bounce_notify_owner_on_removal = Column(Boolean) # XXX
    bounce_score_threshold = Column(Integer) # XXX
    bounce_you_are_disabled_warnings = Column(Integer) # XXX
    bounce_you_are_disabled_warnings_interval = Column(Interval) # XXX
    forward_unrecognized_bounces_to = Column(
        Enum(UnrecognizedBounceDisposition))
    process_bounces = Column(Boolean)
    # Miscellaneous
    default_member_action = Column(Enum(Action))
    default_nonmember_action = Column(Enum(Action))
    description = Column(Unicode)
    digest_footer_uri = Column(Unicode)
    digest_header_uri = Column(Unicode)
    digest_is_default = Column(Boolean)
    digest_send_periodic = Column(Boolean)
    digest_size_threshold = Column(Float)
    digest_volume_frequency = Column(Enum(DigestFrequency))
    digestable = Column(Boolean)
    discard_these_nonmembers = Column(PickleType)
    emergency = Column(Boolean)
    encode_ascii_prefixes = Column(Boolean)
    first_strip_reply_to = Column(Boolean)
    footer_uri = Column(Unicode)
    forward_auto_discards = Column(Boolean)
    gateway_to_mail = Column(Boolean)
    gateway_to_news = Column(Boolean)
    goodbye_message_uri = Column(Unicode)
    header_matches = Column(PickleType)
    header_uri = Column(Unicode)
    hold_these_nonmembers = Column(PickleType)
    info = Column(Unicode)
    linked_newsgroup = Column(Unicode)
    max_days_to_hold = Column(Integer)
    max_message_size = Column(Integer)
    max_num_recipients = Column(Integer)
    member_moderation_notice = Column(Unicode)
    mime_is_default_digest = Column(Boolean)
    # FIXME: There should be no moderator_password
    moderator_password = Column(LargeBinary) # TODO : was RawStr()
    newsgroup_moderation = Column(Enum(NewsgroupModeration))
    nntp_prefix_subject_too = Column(Boolean)
    nondigestable = Column(Boolean)
    nonmember_rejection_notice = Column(Unicode)
    obscure_addresses = Column(Boolean)
    owner_chain = Column(Unicode)
    owner_pipeline = Column(Unicode)
    personalize = Column(Enum(Personalization))
    post_id = Column(Integer)
    posting_chain = Column(Unicode)
    posting_pipeline = Column(Unicode)
    _preferred_language = Column('preferred_language', Unicode)
    display_name = Column(Unicode)
    reject_these_nonmembers = Column(PickleType)
    reply_goes_to_list = Column(Enum(ReplyToMunging))
    reply_to_address = Column(Unicode)
    require_explicit_destination = Column(Boolean)
    respond_to_post_requests = Column(Boolean)
    scrub_nondigest = Column(Boolean)
    send_goodbye_message = Column(Boolean)
    send_welcome_message = Column(Boolean)
    subject_prefix = Column(Unicode)
    subscription_policy = Column(Enum(SubscriptionPolicy))
    topics = Column(PickleType)
    topics_bodylines_limit = Column(Integer)
    topics_enabled = Column(Boolean)
    welcome_message_uri = Column(Unicode)

    def __init__(self, fqdn_listname):
        super(MailingList, self).__init__()
        listname, at, hostname = fqdn_listname.partition('@')
        assert hostname, 'Bad list name: {0}'.format(fqdn_listname)
        self.list_name = listname
        self.mail_host = hostname
        self._list_id = '{0}.{1}'.format(listname, hostname)
        # For the pending database
        self.next_request_id = 1
        # We need to set up the rosters.  Normally, this method will get called
        # when the MailingList object is loaded from the database, but when the
        # constructor is called, SQLAlchemy's `load` event isn't triggered.
        # Thus we need to set up the rosters explicitly.
        self._post_load()
        makedirs(self.data_path)

    def _post_load(self, *args):
        # This hooks up to SQLAlchemy's `load` event.
        self.owners = roster.OwnerRoster(self)
        self.moderators = roster.ModeratorRoster(self)
        self.administrators = roster.AdministratorRoster(self)
        self.members = roster.MemberRoster(self)
        self.regular_members = roster.RegularMemberRoster(self)
        self.digest_members = roster.DigestMemberRoster(self)
        self.subscribers = roster.Subscribers(self)
        self.nonmembers = roster.NonmemberRoster(self)

    @classmethod
    def __declare_last__(cls):
        # SQLAlchemy special directive hook called after mappings are assumed
        # to be complete.  Use this to connect the roster instance creation
        # method with the SA `load` event.
        listen(cls, 'load', cls._post_load)

    def __repr__(self):
        return '<mailing list "{0}" at {1:#x}>'.format(
            self.fqdn_listname, id(self))

    @property
    def fqdn_listname(self):
        """See `IMailingList`."""
        return '{0}@{1}'.format(self.list_name, self.mail_host)

    @property
    def list_id(self):
        """See `IMailingList`."""
        return self._list_id

    @property
    def domain(self):
        """See `IMailingList`."""
        return getUtility(IDomainManager)[self.mail_host]

    @property
    def scheme(self):
        """See `IMailingList`."""
        return self.domain.scheme

    @property
    def web_host(self):
        """See `IMailingList`."""
        return self.domain.url_host

    def script_url(self, target, context=None):
        """See `IMailingList`."""
        # XXX Handle the case for when context is not None; those would be
        # relative URLs.
        return urljoin(self.domain.base_url, target + '/' + self.fqdn_listname)

    @property
    def data_path(self):
        """See `IMailingList`."""
        return os.path.join(config.LIST_DATA_DIR, self.fqdn_listname)

    # IMailingListAddresses

    @property
    def posting_address(self):
        """See `IMailingList`."""
        return self.fqdn_listname

    @property
    def no_reply_address(self):
        """See `IMailingList`."""
        return '{0}@{1}'.format(config.mailman.noreply_address, self.mail_host)

    @property
    def owner_address(self):
        """See `IMailingList`."""
        return '{0}-owner@{1}'.format(self.list_name, self.mail_host)

    @property
    def request_address(self):
        """See `IMailingList`."""
        return '{0}-request@{1}'.format(self.list_name, self.mail_host)

    @property
    def bounces_address(self):
        """See `IMailingList`."""
        return '{0}-bounces@{1}'.format(self.list_name, self.mail_host)

    @property
    def join_address(self):
        """See `IMailingList`."""
        return '{0}-join@{1}'.format(self.list_name, self.mail_host)

    @property
    def leave_address(self):
        """See `IMailingList`."""
        return '{0}-leave@{1}'.format(self.list_name, self.mail_host)

    @property
    def subscribe_address(self):
        """See `IMailingList`."""
        return '{0}-subscribe@{1}'.format(self.list_name, self.mail_host)

    @property
    def unsubscribe_address(self):
        """See `IMailingList`."""
        return '{0}-unsubscribe@{1}'.format(self.list_name, self.mail_host)

    def confirm_address(self, cookie):
        """See `IMailingList`."""
        local_part = expand(config.mta.verp_confirm_format, dict(
            address = '{0}-confirm'.format(self.list_name),
            cookie  = cookie))
        return '{0}@{1}'.format(local_part, self.mail_host)

    @property
    def preferred_language(self):
        """See `IMailingList`."""
        return getUtility(ILanguageManager)[self._preferred_language]

    @preferred_language.setter
    def preferred_language(self, language):
        """See `IMailingList`."""
        # Accept both a language code and a `Language` instance.
        try:
            self._preferred_language = language.code
        except AttributeError:
            self._preferred_language = language

    @dbconnection
    def send_one_last_digest_to(self, store, address, delivery_mode):
        """See `IMailingList`."""
        digest = OneLastDigest(self, address, delivery_mode)
        store.add(digest)

    @property
    @dbconnection
    def last_digest_recipients(self, store):
        """See `IMailingList`."""
        results = store.query(OneLastDigest).filter(
            OneLastDigest.mailing_list == self)
        recipients = [(digest.address, digest.delivery_mode)
                      for digest in results]
        results.delete()
        return recipients

    @property
    @dbconnection
    def filter_types(self, store):
        """See `IMailingList`."""
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.filter_mime)
        for content_filter in results:
            yield content_filter.filter_pattern

    @filter_types.setter
    @dbconnection
    def filter_types(self, store, sequence):
        """See `IMailingList`."""
        # First, delete all existing MIME type filter patterns.
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.filter_mime)
        results.delete()
        # Now add all the new filter types.
        for mime_type in sequence:
            content_filter = ContentFilter(
                self, mime_type, FilterType.filter_mime)
            store.add(content_filter)

    @property
    @dbconnection
    def pass_types(self, store):
        """See `IMailingList`."""
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.pass_mime)
        for content_filter in results:
            yield content_filter.filter_pattern

    @pass_types.setter
    @dbconnection
    def pass_types(self, store, sequence):
        """See `IMailingList`."""
        # First, delete all existing MIME type pass patterns.
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.pass_mime)
        results.delete()
        # Now add all the new filter types.
        for mime_type in sequence:
            content_filter = ContentFilter(
                self, mime_type, FilterType.pass_mime)
            store.add(content_filter)

    @property
    @dbconnection
    def filter_extensions(self, store):
        """See `IMailingList`."""
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.filter_extension)
        for content_filter in results:
            yield content_filter.filter_pattern

    @filter_extensions.setter
    @dbconnection
    def filter_extensions(self, store, sequence):
        """See `IMailingList`."""
        # First, delete all existing file extensions filter patterns.
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.filter_extension)
        results.delete()
        # Now add all the new filter types.
        for mime_type in sequence:
            content_filter = ContentFilter(
                self, mime_type, FilterType.filter_extension)
            store.add(content_filter)

    @property
    @dbconnection
    def pass_extensions(self, store):
        """See `IMailingList`."""
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.pass_extension)
        for content_filter in results:
            yield content_filter.pass_pattern

    @pass_extensions.setter
    @dbconnection
    def pass_extensions(self, store, sequence):
        """See `IMailingList`."""
        # First, delete all existing file extensions pass patterns.
        results = store.query(ContentFilter).filter(
            ContentFilter.mailing_list == self,
            ContentFilter.filter_type == FilterType.pass_extension)
        results.delete()
        # Now add all the new filter types.
        for mime_type in sequence:
            content_filter = ContentFilter(
                self, mime_type, FilterType.pass_extension)
            store.add(content_filter)

    def get_roster(self, role):
        """See `IMailingList`."""
        if role is MemberRole.member:
            return self.members
        elif role is MemberRole.owner:
            return self.owners
        elif role is MemberRole.moderator:
            return self.moderators
        elif role is MemberRole.nonmember:
            return self.nonmembers
        else:
            raise TypeError('Undefined MemberRole: {}'.format(role))

    @dbconnection
    def subscribe(self, store, subscriber, role=MemberRole.member):
        """See `IMailingList`."""
        if IAddress.providedBy(subscriber):
            member = store.query(Member).filter(
                Member.role == role,
                Member.list_id == self._list_id,
                Member._address == subscriber).first()
            if member:
                raise AlreadySubscribedError(
                    self.fqdn_listname, subscriber.email, role)
        elif IUser.providedBy(subscriber):
            if subscriber.preferred_address is None:
                raise MissingPreferredAddressError(subscriber)
            member = store.query(Member).filter(
                Member.role == role,
                Member.list_id == self._list_id,
                Member._user == subscriber).first()
            if member:
                raise AlreadySubscribedError(
                    self.fqdn_listname,
                    subscriber.preferred_address.email,
                    role)
        else:
            raise ValueError('subscriber must be an address or user')
        member = Member(role=role,
                        list_id=self._list_id,
                        subscriber=subscriber)
        member.preferences = Preferences()
        store.add(member)
        notify(SubscriptionEvent(self, member))
        return member



@implementer(IAcceptableAlias)
class AcceptableAlias(Model):
    """See `IAcceptableAlias`."""

    __tablename__ = 'acceptablealias'

    id = Column(Integer, primary_key=True)

    mailing_list_id = Column(
        Integer, ForeignKey('mailinglist.id'),
        index=True, nullable=False)
    mailing_list = relationship('MailingList', backref='acceptablealias')
    alias = Column(Unicode, index=True, nullable=False)

    def __init__(self, mailing_list, alias):
        super(AcceptableAlias, self).__init__()
        self.mailing_list = mailing_list
        self.alias = alias



@implementer(IAcceptableAliasSet)
class AcceptableAliasSet:
    """See `IAcceptableAliasSet`."""

    def __init__(self, mailing_list):
        self._mailing_list = mailing_list

    @dbconnection
    def clear(self, store):
        """See `IAcceptableAliasSet`."""
        store.query(AcceptableAlias).filter(
            AcceptableAlias.mailing_list == self._mailing_list).delete()

    @dbconnection
    def add(self, store, alias):
        if not (alias.startswith('^') or '@' in alias):
            raise ValueError(alias)
        alias = AcceptableAlias(self._mailing_list, alias.lower())
        store.add(alias)

    @dbconnection
    def remove(self, store, alias):
        store.query(AcceptableAlias).filter(
            AcceptableAlias.mailing_list == self._mailing_list,
            AcceptableAlias.alias == alias.lower()).delete()

    @property
    @dbconnection
    def aliases(self, store):
        aliases = store.query(AcceptableAlias).filter(
            AcceptableAlias.mailing_list_id == self._mailing_list.id)
        for alias in aliases:
            yield alias.alias



@implementer(IListArchiver)
class ListArchiver(Model):
    """See `IListArchiver`."""

    __tablename__ = 'listarchiver'

    id = Column(Integer, primary_key=True)

    mailing_list_id = Column(
        Integer, ForeignKey('mailinglist.id'),
        index=True, nullable=False)
    mailing_list = relationship('MailingList')

    name = Column(Unicode, nullable=False)
    _is_enabled = Column(Boolean)

    def __init__(self, mailing_list, archiver_name, system_archiver):
        self.mailing_list = mailing_list
        self.name = archiver_name
        self._is_enabled = system_archiver.is_enabled

    @property
    def system_archiver(self):
        for archiver in config.archivers:
            if archiver.name == self.name:
                return archiver
        return None

    @property
    def is_enabled(self):
        return self.system_archiver.is_enabled and self._is_enabled

    @is_enabled.setter
    def is_enabled(self, value):
        self._is_enabled = value


@implementer(IListArchiverSet)
class ListArchiverSet:
    @dbconnection
    def __init__(self, store, mailing_list):
        self._mailing_list = mailing_list
        system_archivers = {}
        for archiver in config.archivers:
            system_archivers[archiver.name] = archiver
        # Add any system enabled archivers which aren't already associated
        # with the mailing list.
        for archiver_name in system_archivers:
            exists = store.query(ListArchiver).filter(
                ListArchiver.mailing_list == mailing_list,
                ListArchiver.name == archiver_name).one_or_none()
            if exists is None:
                store.add(ListArchiver(mailing_list, archiver_name,
                                       system_archivers[archiver_name]))

    @property
    @dbconnection
    def archivers(self, store):
        entries = store.query(ListArchiver).filter(
            ListArchiver.mailing_list == self._mailing_list)
        for entry in entries:
            yield entry

    @dbconnection
    def get(self, store, archiver_name):
        return store.query(ListArchiver).filter(
            ListArchiver.mailing_list == self._mailing_list,
            ListArchiver.name == archiver_name).one_or_none()
