# Copyright (C) 2007-2016 by the Free Software Foundation, Inc.
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

"""Sending notifications."""

__all__ = [
    'send_admin_subscription_notice',
    'send_goodbye_message',
    'send_welcome_message',
    ]


import logging

from email.utils import formataddr
from lazr.config import as_boolean
from mailman.config import config
from mailman.core.i18n import _
from mailman.email.message import OwnerNotification, UserNotification
from mailman.interfaces.member import DeliveryMode
from mailman.interfaces.templates import ITemplateLoader
from mailman.utilities.i18n import make
from mailman.utilities.string import expand, wrap
from urllib.error import URLError
from zope.component import getUtility


log = logging.getLogger('mailman.error')



def _get_message(uri_template, mlist, language):
    if not uri_template:
        return ''
    try:
        uri = expand(uri_template, dict(
            listname=mlist.fqdn_listname,
            language=language.code,
            ))
        message = getUtility(ITemplateLoader).get(uri)
    except URLError:
        log.exception('Message URI not found ({0}): {1}'.format(
            mlist.fqdn_listname, uri_template))
        return ''
    else:
        return wrap(message)



def send_welcome_message(mlist, member, language, text=''):
    """Send a welcome message to a subscriber.

    Prepending to the standard welcome message template is the mailing list's
    welcome message, if there is one.

    :param mlist: The mailing list.
    :type mlist: IMailingList
    :param member: The member to send the welcome message to.
    :param address: IMember
    :param language: The language of the response.
    :type language: ILanguage
    """
    welcome_message = _get_message(mlist.welcome_message_uri, mlist, language)
    options_url = member.options_url
    # Get the text from the template.
    display_name = ('' if member.user is None else member.user.display_name)
    text = expand(welcome_message, dict(
        fqdn_listname=mlist.fqdn_listname,
        list_name=mlist.display_name,
        listinfo_uri=mlist.script_url('listinfo'),
        list_requests=mlist.request_address,
        user_name=display_name,
        user_address=member.address.email,
        user_options_uri=options_url,
        ))
    digmode = ('' if member.delivery_mode is DeliveryMode.regular
               else _(' (Digest mode)'))
    msg = UserNotification(
        formataddr((display_name, member.address.email)),
        mlist.request_address,
        _('Welcome to the "$mlist.display_name" mailing list${digmode}'),
        text, language)
    msg['X-No-Archive'] = 'yes'
    msg.send(mlist, verp=as_boolean(config.mta.verp_personalized_deliveries))



def send_goodbye_message(mlist, address, language):
    """Send a goodbye message to a subscriber.

    Prepending to the standard goodbye message template is the mailing list's
    goodbye message, if there is one.

    :param mlist: the mailing list
    :type mlist: IMailingList
    :param address: The address to respond to
    :type address: string
    :param language: the language of the response
    :type language: string
    """
    goodbye_message = _get_message(mlist.goodbye_message_uri,
                                   mlist, language)
    msg = UserNotification(
        address, mlist.bounces_address,
        _('You have been unsubscribed from the $mlist.display_name '
          'mailing list'),
        goodbye_message, language)
    msg.send(mlist, verp=as_boolean(config.mta.verp_personalized_deliveries))



def send_admin_subscription_notice(mlist, address, display_name):
    """Send the list administrators a subscription notice.

    :param mlist: The mailing list.
    :type mlist: IMailingList
    :param address: The address being subscribed.
    :type address: string
    :param display_name: The name of the subscriber.
    :type display_name: string
    """
    with _.using(mlist.preferred_language.code):
        subject = _('$mlist.display_name subscription notification')
    text = make('adminsubscribeack.txt',
                mailing_list=mlist,
                listname=mlist.display_name,
                member=formataddr((display_name, address)),
                )
    msg = OwnerNotification(mlist, subject, text, roster=mlist.administrators)
    msg.send(mlist)
