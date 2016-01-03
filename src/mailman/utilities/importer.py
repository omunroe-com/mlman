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

"""Importer routines."""

__all__ = [
    'Import21Error',
    'import_config_pck',
    ]


import os
import sys
import codecs
import datetime

from mailman.config import config
from mailman.core.errors import MailmanError
from mailman.handlers.decorate import decorate, decorate_template
from mailman.interfaces.action import Action, FilterAction
from mailman.interfaces.address import IEmailValidator
from mailman.interfaces.archiver import ArchivePolicy
from mailman.interfaces.autorespond import ResponseAction
from mailman.interfaces.bans import IBanManager
from mailman.interfaces.bounce import UnrecognizedBounceDisposition
from mailman.interfaces.digests import DigestFrequency
from mailman.interfaces.languages import ILanguageManager
from mailman.interfaces.mailinglist import IAcceptableAliasSet
from mailman.interfaces.mailinglist import Personalization, ReplyToMunging
from mailman.interfaces.mailinglist import SubscriptionPolicy
from mailman.interfaces.member import DeliveryMode, DeliveryStatus, MemberRole
from mailman.interfaces.nntp import NewsgroupModeration
from mailman.interfaces.usermanager import IUserManager
from mailman.utilities.filesystem import makedirs
from mailman.utilities.i18n import search
from sqlalchemy import Boolean
from urllib.error import URLError
from zope.component import getUtility



class Import21Error(MailmanError):
    """An import from a Mailman 2.1 list failed."""



def bytes_to_str(value):
    # Convert a string to unicode when the encoding is not declared.
    if not isinstance(value, bytes):
        return value
    for encoding in ('ascii', 'utf-8'):
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            continue
    # We did our best, use replace.
    return value.decode('ascii', 'replace')


def str_to_bytes(value):
    if value is None or isinstance(value, bytes):
        return value
    return value.encode('utf-8')


def seconds_to_delta(value):
    return datetime.timedelta(seconds=value)


def days_to_delta(value):
    return datetime.timedelta(days=value)


def list_members_to_unicode(value):
    return [bytes_to_str(item) for item in value]



def filter_action_mapping(value):
    # The filter_action enum values have changed.  In Mailman 2.1 the order
    # was 'Discard', 'Reject', 'Forward to List Owner', 'Preserve'.  In MM3
    # it's 'hold', 'reject', 'discard', 'accept', 'defer', 'forward',
    # 'preserve'.  Some of the MM3 actions don't exist in MM2.1.
    return {
        0: FilterAction.discard,
        1: FilterAction.reject,
        2: FilterAction.forward,
        3: FilterAction.preserve,
        }[value]



def member_action_mapping(value):
    # The mlist.default_member_action and mlist.default_nonmember_action enum
    # values are different in Mailman 2.1, because they have been merged into
    # a single enum in Mailman 3.
    #
    # For default_member_action, which used to be called
    # member_moderation_action, the values were: 0==Hold, 1=Reject, 2==Discard
    return {
        0: Action.hold,
        1: Action.reject,
        2: Action.discard,
        }[value]


def nonmember_action_mapping(value):
    # For default_nonmember_action, which used to be called
    # generic_nonmember_action, the values were: 0==Accept, 1==Hold,
    # 2==Reject, 3==Discard
    return {
        0: Action.accept,
        1: Action.hold,
        2: Action.reject,
        3: Action.discard,
        }[value]



def check_language_code(code):
    if code is None:
        return None
    code = bytes_to_str(code)
    if code not in getUtility(ILanguageManager):
        msg = """Missing language: {0}
You must add a section describing this language to your mailman.cfg file.
This section should look like this:
[language.{0}]
# The English name for this language.
description: CHANGE ME
# The default character set for this language.
charset: utf-8
# Whether the language is enabled or not.
enabled: yes
""".format(code)
        raise Import21Error(msg)
    return code



# Attributes in Mailman 2 which have a different type in Mailman 3.  Some
# types (e.g. bools) are autodetected from their SA column types.
TYPES = dict(
    autorespond_owner=ResponseAction,
    autorespond_postings=ResponseAction,
    autorespond_requests=ResponseAction,
    autoresponse_grace_period=days_to_delta,
    bounce_info_stale_after=seconds_to_delta,
    bounce_you_are_disabled_warnings_interval=seconds_to_delta,
    default_member_action=member_action_mapping,
    default_nonmember_action=nonmember_action_mapping,
    digest_volume_frequency=DigestFrequency,
    filter_action=filter_action_mapping,
    filter_extensions=list_members_to_unicode,
    filter_types=list_members_to_unicode,
    forward_unrecognized_bounces_to=UnrecognizedBounceDisposition,
    moderator_password=str_to_bytes,
    newsgroup_moderation=NewsgroupModeration,
    pass_extensions=list_members_to_unicode,
    pass_types=list_members_to_unicode,
    personalize=Personalization,
    preferred_language=check_language_code,
    reply_goes_to_list=ReplyToMunging,
    subscription_policy=SubscriptionPolicy,
    )


# Attribute names in Mailman 2 which are renamed in Mailman 3.
NAME_MAPPINGS = dict(
    autorespond_admin='autorespond_owner',
    autoresponse_admin_text='autoresponse_owner_text',
    autoresponse_graceperiod='autoresponse_grace_period',
    bounce_processing='process_bounces',
    bounce_unrecognized_goes_to_list_owner='forward_unrecognized_bounces_to',
    filter_filename_extensions='filter_extensions',
    filter_mime_types='filter_types',
    generic_nonmember_action='default_nonmember_action',
    include_list_post_header='allow_list_posts',
    member_moderation_action='default_member_action',
    mod_password='moderator_password',
    news_moderation='newsgroup_moderation',
    news_prefix_subject_too='nntp_prefix_subject_too',
    pass_filename_extensions='pass_extensions',
    pass_mime_types='pass_types',
    real_name='display_name',
    send_goodbye_msg='send_goodbye_message',
    send_welcome_msg='send_welcome_message',
    subscribe_policy='subscription_policy',
    )

# These DateTime fields of the mailinglist table need a type conversion to
# Python datetime object for SQLite databases.
DATETIME_COLUMNS = [
    'created_at',
    'digest_last_sent_at',
    'last_post_time',
    ]

EXCLUDES = set((
    'delivery_status',
    'digest_members',
    'members',
    'user_options',
    ))



def import_config_pck(mlist, config_dict):
    """Apply a config.pck configuration dictionary to a mailing list.

    :param mlist: The mailing list.
    :type mlist: IMailingList
    :param config_dict: The Mailman 2.1 configuration dictionary.
    :type config_dict: dict
    """
    for key, value in config_dict.items():
        # Some attributes must not be directly imported.
        if key in EXCLUDES:
            continue
        # These objects need explicit type conversions.
        if key in DATETIME_COLUMNS:
            continue
        # Some attributes from Mailman 2 were renamed in Mailman 3.
        key = NAME_MAPPINGS.get(key, key)
        # Handle the simple case where the key is an attribute of the
        # IMailingList and the types are the same (modulo 8-bit/unicode
        # strings).
        #
        # If the mailing list has a preferred language that isn't registered
        # in the configuration file, hasattr() will swallow the KeyError this
        # raises and return False.  Treat that attribute specially.
        if key == 'preferred_language' or hasattr(mlist, key):
            if isinstance(value, bytes):
                value = bytes_to_str(value)
            # Some types require conversion.
            converter = TYPES.get(key)
            if converter is None:
                column = getattr(mlist.__class__, key, None)
                if column is not None and isinstance(column.type, Boolean):
                    converter = bool
            try:
                if converter is not None:
                    value = converter(value)
                setattr(mlist, key, value)
            except (TypeError, KeyError):
                print('Type conversion error for key "{}": {}'.format(
                    key, value), file=sys.stderr)
    for key in DATETIME_COLUMNS:
        try:
            value = datetime.datetime.utcfromtimestamp(config_dict[key])
        except KeyError:
            continue
        if key == 'last_post_time':
            setattr(mlist, 'last_post_at', value)
            continue
        setattr(mlist, key, value)
    # Handle the archiving policy.  In MM2.1 there were two boolean options
    # but only three of the four possible states were valid.  Now there's just
    # an enum.
    if config_dict.get('archive'):
        # For maximum safety, if for some strange reason there's no
        # archive_private key, treat the list as having private archives.
        if config_dict.get('archive_private', True):
            mlist.archive_policy = ArchivePolicy.private
        else:
            mlist.archive_policy = ArchivePolicy.public
    else:
        mlist.archive_policy = ArchivePolicy.never
    # Handle ban list.
    ban_manager = IBanManager(mlist)
    for address in config_dict.get('ban_list', []):
        ban_manager.ban(bytes_to_str(address))
    # Handle acceptable aliases.
    acceptable_aliases = config_dict.get('acceptable_aliases', '')
    if isinstance(acceptable_aliases, bytes):
        acceptable_aliases = acceptable_aliases.decode('utf-8')
    if isinstance(acceptable_aliases, str):
        acceptable_aliases = acceptable_aliases.splitlines()
    alias_set = IAcceptableAliasSet(mlist)
    for address in acceptable_aliases:
        address = address.strip()
        if len(address) == 0:
            continue
        address = bytes_to_str(address)
        try:
            alias_set.add(address)
        except ValueError:
            # When .add() rejects this, the line probably contains a regular
            # expression.  Make that explicit for MM3.
            alias_set.add('^' + address)
    # Handle conversion to URIs.  In MM2.1, the decorations are strings
    # containing placeholders, and there's no provision for language-specific
    # templates.  In MM3, template locations are specified by URLs with the
    # special `mailman:` scheme indicating a file system path.  What we do
    # here is look to see if the list's decoration is different than the
    # default, and if so, we'll write the new decoration template to a
    # `mailman:` scheme path.
    convert_to_uri = {
        'welcome_msg': 'welcome_message_uri',
        'goodbye_msg': 'goodbye_message_uri',
        'msg_header': 'header_uri',
        'msg_footer': 'footer_uri',
        'digest_header': 'digest_header_uri',
        'digest_footer': 'digest_footer_uri',
        }
    # The best we can do is convert only the most common ones.  These are
    # order dependent; the longer substitution with the common prefix must
    # show up earlier.
    convert_placeholders = [
        ('%(real_name)s@%(host_name)s', '$fqdn_listname'),
        ('%(real_name)s', '$display_name'),
        ('%(web_page_url)slistinfo%(cgiext)s/%(_internal_name)s',
         '$listinfo_uri'),
        ]
    # Collect defaults.
    defaults = {}
    for oldvar, newvar in convert_to_uri.items():
        default_value = getattr(mlist, newvar, None)
        if not default_value:
            continue
        # Check if the value changed from the default.
        try:
            default_text = decorate(mlist, default_value)
        except (URLError, KeyError):
            # Use case: importing the old a@ex.com into b@ex.com.  We can't
            # check if it changed from the default so don't import, we may do
            # more harm than good and it's easy to change if needed.
            # TESTME
            print('Unable to convert mailing list attribute:', oldvar,
                  'with old value "{}"'.format(default_value),
                  file=sys.stderr)
            continue
        defaults[newvar] = (default_value, default_text)
    for oldvar, newvar in convert_to_uri.items():
        if oldvar not in config_dict:
            continue
        text = config_dict[oldvar]
        if isinstance(text, bytes):
            text = text.decode('utf-8', 'replace')
        for oldph, newph in convert_placeholders:
            text = text.replace(oldph, newph)
        default_value, default_text  = defaults.get(newvar, (None, None))
        if not text and not (default_value or default_text):
            # Both are empty, leave it.
            continue
        # Check if the value changed from the default
        try:
            expanded_text = decorate_template(mlist, text)
        except KeyError:
            # Use case: importing the old a@ex.com into b@ex.com
            # We can't check if it changed from the default
            # -> don't import, we may do more harm than good and it's easy to
            # change if needed
            # TESTME
            print('Unable to convert mailing list attribute:', oldvar,
                  'with value "{}"'.format(text),
                  file=sys.stderr)
            continue
        if (expanded_text and default_text
                and expanded_text.strip() == default_text.strip()):
            # Keep the default.
            continue
        # Write the custom value to the right file.
        base_uri = 'mailman:///$listname/$language/'
        if default_value:
            filename = default_value.rpartition('/')[2]
        else:
            filename = '{}.txt'.format(newvar[:-4])
        if not default_value or not default_value.startswith(base_uri):
            setattr(mlist, newvar, base_uri + filename)
        filepath = list(search(filename, mlist))[0]
        makedirs(os.path.dirname(filepath))
        with codecs.open(filepath, 'w', encoding='utf-8') as fp:
            fp.write(text)
    # Import rosters.
    regulars_set = set(config_dict.get('members', {}))
    digesters_set = set(config_dict.get('digest_members', {}))
    members = regulars_set.union(digesters_set)
    # Don't send welcome messages when we import the rosters.
    send_welcome_message = mlist.send_welcome_message
    mlist.send_welcome_message = False
    try:
        import_roster(mlist, config_dict, members, MemberRole.member)
        import_roster(mlist, config_dict, config_dict.get('owner', []),
                      MemberRole.owner)
        import_roster(mlist, config_dict, config_dict.get('moderator', []),
                      MemberRole.moderator)
    finally:
        mlist.send_welcome_message = send_welcome_message



def import_roster(mlist, config_dict, members, role):
    """Import members lists from a config.pck configuration dictionary.

    :param mlist: The mailing list.
    :type mlist: IMailingList
    :param config_dict: The Mailman 2.1 configuration dictionary.
    :type config_dict: dict
    :param members: The members list to import.
    :type members: list
    :param role: The MemberRole to import them as.
    :type role: MemberRole enum
    """
    usermanager = getUtility(IUserManager)
    validator = getUtility(IEmailValidator)
    roster = mlist.get_roster(role)
    for email in members:
        # For owners and members, the emails can have a mixed case, so
        # lowercase them all.
        email = bytes_to_str(email).lower()
        if roster.get_member(email) is not None:
            print('{} is already imported with role {}'.format(email, role),
                  file=sys.stderr)
            continue
        address = usermanager.get_address(email)
        user = usermanager.get_user(email)
        if user is None:
            user = usermanager.create_user()
            if address is None:
                merged_members = {}
                merged_members.update(config_dict.get('members', {}))
                merged_members.update(config_dict.get('digest_members', {}))
                if merged_members.get(email, 0) != 0:
                    original_email = bytes_to_str(merged_members[email])
                    if not validator.is_valid(original_email):
                        original_email = email
                else:
                    original_email = email
                if not validator.is_valid(original_email):
                    # Skip this one entirely.
                    continue
                address = usermanager.create_address(original_email)
                address.verified_on = datetime.datetime.now()
            user.link(address)
        mlist.subscribe(address, role)
        member = roster.get_member(email)
        assert member is not None
        prefs = config_dict.get('user_options', {}).get(email, 0)
        if email in config_dict.get('members', {}):
            member.preferences.delivery_mode = DeliveryMode.regular
        elif email in config_dict.get('digest_members', {}):
            if prefs & 8: # DisableMime
                member.preferences.delivery_mode = \
                  DeliveryMode.plaintext_digests
            else:
                member.preferences.delivery_mode = DeliveryMode.mime_digests
        else:
            # XXX Probably not adding a member role here.
            pass
        if email in config_dict.get('language', {}):
            member.preferences.preferred_language = \
                check_language_code(config_dict['language'][email])
        # If the user already exists, display_name and password will be
        # overwritten.
        if email in config_dict.get('usernames', {}):
            address.display_name = \
                bytes_to_str(config_dict['usernames'][email])
            user.display_name    = \
                bytes_to_str(config_dict['usernames'][email])
        if email in config_dict.get('passwords', {}):
            user.password = config.password_context.encrypt(
                config_dict['passwords'][email])
        # delivery_status
        oldds = config_dict.get('delivery_status', {}).get(email, (0, 0))[0]
        if oldds == 0:
            member.preferences.delivery_status = DeliveryStatus.enabled
        elif oldds == 1:
            member.preferences.delivery_status = DeliveryStatus.unknown
        elif oldds == 2:
            member.preferences.delivery_status = DeliveryStatus.by_user
        elif oldds == 3:
            member.preferences.delivery_status = DeliveryStatus.by_moderator
        elif oldds == 4:
            member.preferences.delivery_status = DeliveryStatus.by_bounces
        # Moderation.
        if prefs & 128:
            member.moderation_action = Action.hold
        # Other preferences.
        #
        # AcknowledgePosts
        member.preferences.acknowledge_posts = bool(prefs & 4)
        # ConcealSubscription
        member.preferences.hide_address = bool(prefs & 16)
        # DontReceiveOwnPosts
        member.preferences.receive_own_postings = not bool(prefs & 2)
        # DontReceiveDuplicates
        member.preferences.receive_list_copy = not bool(prefs & 256)
