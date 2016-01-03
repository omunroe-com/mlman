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

"""Interface describing a user registration service.

This is a higher level interface to user registration, address confirmation,
etc. than the IUserManager.  The latter does no validation, syntax checking,
or confirmation, while this interface does.
"""

__all__ = [
    'ConfirmationNeededEvent',
    'IRegistrar',
    ]


from zope.interface import Interface



class ConfirmationNeededEvent:
    """Triggered when an address needs confirmation.

    Addresses must be verified before they can receive messages or post
    to mailing list.  The confirmation message is sent to the user when
    this event is triggered.
    """
    def __init__(self, mlist, token, email):
        self.mlist = mlist
        self.token = token
        self.email = email



class IRegistrar(Interface):
    """Interface for subscribing addresses and users.

    This is a higher level interface to user registration, email address
    confirmation, etc. than the IUserManager.  The latter does no validation,
    syntax checking, or confirmation, while this interface does.

    To use this, adapt an ``IMailingList`` to this interface.
    """

    def register(subscriber=None, *,
                 pre_verified=False, pre_confirmed=False, pre_approved=False):
        """Subscribe an address or user according to subscription policies.

        The mailing list's subscription policy is used to subscribe
        `subscriber` to the given mailing list.  The subscriber can be
        an ``IUser``, in which case the user must have a preferred
        address, and that preferred address will be subscribed.  The
        subscriber can also be an ``IAddress``, in which case the
        address will be subscribed.

        The workflow may pause (i.e. be serialized, saved, and
        suspended) when some out-of-band confirmation step is required.
        For example, if the user must confirm, or the moderator must
        approve the subscription.  Use the ``confirm(token)`` method to
        resume the workflow.

        :param subscriber: The user or address to subscribe.
        :type email: ``IUser`` or ``IAddress``
        :return: A 3-tuple is returned where the first element is the token
            hash, the second element is a ``TokenOwner`, and the third element
            is the subscribed member.  If the subscriber got subscribed
            immediately, the token will be None and the member will be
            an ``IMember``.  If the subscription got held, the token
            will be a hash and the member will be None.
        :rtype: (str-or-None, ``TokenOwner``, ``IMember``-or-None)
        :raises MembershipIsBannedError: when the address being subscribed
            appears in the global or list-centric bans.
        """

    def confirm(token):
        """Continue any paused workflow.

        Confirmation may occur after the user confirms their
        subscription request, or their email address must be verified,
        or the moderator must approve the subscription request.

        :param token: A token matching a workflow.
        :type token: string
        :return: A 3-tuple is returned where the first element is the token
            hash, the second element is a ``TokenOwner`, and the third element
            is the subscribed member.  If the subscriber got subscribed
            immediately, the token will be None and the member will be
            an ``IMember``.  If the subscription is still being held, the token
            will be a hash and the member will be None.
        :rtype: (str-or-None, ``TokenOwner``, ``IMember``-or-None)
        :raises LookupError: when no workflow is associated with the token.
        """

    def discard(token):
        """Discard the workflow matched to the given `token`.

        :param token: A token matching a pending event with a type of
            'registration'.
        :raises LookupError: when no workflow is associated with the token.
        """

    def evict():
        """Evict all saved workflows which have expired."""
