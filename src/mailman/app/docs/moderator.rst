.. _app-moderator:

============================
Application level moderation
============================

At an application level, moderation involves holding messages and membership
changes for moderator approval.  This utilizes the :ref:`lower level interface
<model-requests>` for list-centric moderation requests.

Moderation is always mailing list-centric.

    >>> mlist = create_list('ant@example.com')
    >>> mlist.preferred_language = 'en'
    >>> mlist.display_name = 'A Test List'
    >>> mlist.admin_immed_notify = False

We'll use the lower level API for diagnostic purposes.

    >>> from mailman.interfaces.requests import IListRequests
    >>> requests = IListRequests(mlist)


Message moderation
==================

Holding messages
----------------

Anne posts a message to the mailing list, but she is not a member of the list,
so the message is held for moderator approval.

    >>> msg = message_from_string("""\
    ... From: anne@example.org
    ... To: ant@example.com
    ... Subject: Something important
    ... Message-ID: <aardvark>
    ...
    ... Here's something important about our mailing list.
    ... """)

*Holding a message* means keeping a copy of it that a moderator must approve
before the message is posted to the mailing list.  To hold the message, the
message, its metadata, and a reason for the hold must be provided.  In this
case, we won't include any additional metadata.

    >>> from mailman.app.moderator import hold_message
    >>> hold_message(mlist, msg, {}, 'Needs approval')
    1

We can also hold a message with some additional metadata.
::

    >>> msg = message_from_string("""\
    ... From: bart@example.org
    ... To: ant@example.com
    ... Subject: Something important
    ... Message-ID: <badger>
    ...
    ... Here's something important about our mailing list.
    ... """)
    >>> msgdata = dict(sender='anne@example.com', approved=True)

    >>> hold_message(mlist, msg, msgdata, 'Feeling ornery')
    2


Disposing of messages
---------------------

The moderator can select one of several dispositions:

  * discard - throw the message away.
  * reject - bounces the message back to the original author.
  * defer - defer any action on the message (continue to hold it)
  * accept - accept the message for posting.

The most trivial is to simply defer a decision for now.

    >>> from mailman.interfaces.action import Action
    >>> from mailman.app.moderator import handle_message
    >>> handle_message(mlist, 1, Action.defer)

This leaves the message in the requests database.

    >>> key, data = requests.get_request(1)
    >>> print(key)
    <aardvark>

The moderator can also discard the message.

    >>> handle_message(mlist, 1, Action.discard)
    >>> print(requests.get_request(1))
    None

The message can be rejected, which bounces the message back to the original
sender.

    >>> handle_message(mlist, 2, Action.reject, 'Off topic')

The message is no longer available in the requests database.

    >>> print(requests.get_request(2))
    None

And there is one message in the *virgin* queue - the rejection notice.

    >>> from mailman.testing.helpers import get_queue_messages
    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: Request to mailing list "A Test List" rejected
    From: ant-bounces@example.com
    To: bart@example.org
    ...
    <BLANKLINE>
    Your request to the ant@example.com mailing list
    <BLANKLINE>
        Posting of your message titled "Something important"
    <BLANKLINE>
    has been rejected by the list moderator.  The moderator gave the
    following reason for rejecting your request:
    <BLANKLINE>
    "Off topic"
    <BLANKLINE>
    Any questions or comments should be directed to the list administrator
    at:
    <BLANKLINE>
        ant-owner@example.com
    <BLANKLINE>

The bounce gets sent to the original sender.

    >>> for recipient in sorted(messages[0].msgdata['recipients']):
    ...     print(recipient)
    bart@example.org

Or the message can be approved.

    >>> msg = message_from_string("""\
    ... From: cris@example.org
    ... To: ant@example.com
    ... Subject: Something important
    ... Message-ID: <caribou>
    ...
    ... Here's something important about our mailing list.
    ... """)
    >>> id = hold_message(mlist, msg, {}, 'Needs approval')
    >>> handle_message(mlist, id, Action.accept)

This places the message back into the incoming queue for further processing,
however the message metadata indicates that the message has been approved.
::

    >>> messages = get_queue_messages('pipeline')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    From: cris@example.org
    To: ant@example.com
    Subject: Something important
    ...

    >>> dump_msgdata(messages[0].msgdata)
    _parsemsg         : False
    approved          : True
    moderator_approved: True
    version           : 3


Forwarding the message
----------------------

The message can be forwarded to another address.  This is helpful for getting
the message into the inbox of one of the moderators.
::

    >>> msg = message_from_string("""\
    ... From: elly@example.org
    ... To: ant@example.com
    ... Subject: Something important
    ... Message-ID: <elephant>
    ...
    ... Here's something important about our mailing list.
    ... """)
    >>> req_id = hold_message(mlist, msg, {}, 'Needs approval')
    >>> handle_message(mlist, req_id, Action.discard,
    ...                forward=['zack@example.com'])

The forwarded message is in the virgin queue, destined for the moderator.
::

    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    Subject: Forward of moderated message
    From: ant-bounces@example.com
    To: zack@example.com
    ...

    >>> for recipient in sorted(messages[0].msgdata['recipients']):
    ...     print(recipient)
    zack@example.com


Holding subscription requests
=============================

For closed lists, subscription requests will also be held for moderator
approval.  In this case, several pieces of information related to the
subscription must be provided, including the subscriber's address and real
name, what kind of delivery option they are choosing and their preferred
language.

    >>> from mailman.app.moderator import hold_subscription
    >>> from mailman.interfaces.member import DeliveryMode
    >>> from mailman.interfaces.subscriptions import RequestRecord
    >>> req_id = hold_subscription(
    ...     mlist,
    ...     RequestRecord('fred@example.org', 'Fred Person',
    ...                   DeliveryMode.regular, 'en'))


Disposing of membership change requests
---------------------------------------

Just as with held messages, the moderator can select one of several
dispositions for this membership change request.  The most trivial is to
simply defer a decision for now.

    >>> from mailman.app.moderator import handle_subscription
    >>> handle_subscription(mlist, req_id, Action.defer)
    >>> requests.get_request(req_id) is not None
    True

The held subscription can also be discarded.

    >>> handle_subscription(mlist, req_id, Action.discard)
    >>> print(requests.get_request(req_id))
    None

Gwen tries to subscribe to the mailing list, but...

    >>> req_id = hold_subscription(
    ...     mlist,
    ...     RequestRecord('gwen@example.org', 'Gwen Person',
    ...                   DeliveryMode.regular, 'en'))


...her request is rejected...

    >>> handle_subscription(
    ...     mlist, req_id, Action.reject, 'This is a closed list')
    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1

...and she receives a rejection notice.

    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: Request to mailing list "A Test List" rejected
    From: ant-bounces@example.com
    To: gwen@example.org
    ...
    Your request to the ant@example.com mailing list
    <BLANKLINE>
        Subscription request
    <BLANKLINE>
    has been rejected by the list moderator.  The moderator gave the
    following reason for rejecting your request:
    <BLANKLINE>
    "This is a closed list"
    ...

The subscription can also be accepted.  This subscribes the address to the
mailing list.

    >>> mlist.send_welcome_message = False
    >>> req_id = hold_subscription(
    ...     mlist,
    ...     RequestRecord('herb@example.org', 'Herb Person',
    ...                   DeliveryMode.regular, 'en'))

The moderators accept the subscription request.

    >>> handle_subscription(mlist, req_id, Action.accept)

And now Herb is a member of the mailing list.

    >>> print(mlist.members.get_member('herb@example.org').address)
    Herb Person <herb@example.org>


Holding unsubscription requests
===============================

Some lists require moderator approval for unsubscriptions.  In this case, only
the unsubscribing address is required.

Herb now wants to leave the mailing list, but his request must be approved.

    >>> from mailman.app.moderator import hold_unsubscription
    >>> req_id = hold_unsubscription(mlist, 'herb@example.org')

As with subscription requests, the unsubscription request can be deferred.

    >>> from mailman.app.moderator import handle_unsubscription
    >>> handle_unsubscription(mlist, req_id, Action.defer)
    >>> print(mlist.members.get_member('herb@example.org').address)
    Herb Person <herb@example.org>

The held unsubscription can also be discarded, and the member will remain
subscribed.

    >>> handle_unsubscription(mlist, req_id, Action.discard)
    >>> print(mlist.members.get_member('herb@example.org').address)
    Herb Person <herb@example.org>

The request can be rejected, in which case a message is sent to the member,
and the person remains a member of the mailing list.

    >>> req_id = hold_unsubscription(mlist, 'herb@example.org')
    >>> handle_unsubscription(mlist, req_id, Action.reject, 'No can do')
    >>> print(mlist.members.get_member('herb@example.org').address)
    Herb Person <herb@example.org>

Herb gets a rejection notice.
::

    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1

    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: Request to mailing list "A Test List" rejected
    From: ant-bounces@example.com
    To: herb@example.org
    ...
    Your request to the ant@example.com mailing list
    <BLANKLINE>
        Unsubscription request
    <BLANKLINE>
    has been rejected by the list moderator.  The moderator gave the
    following reason for rejecting your request:
    <BLANKLINE>
    "No can do"
    ...

The unsubscription request can also be accepted.  This removes the member from
the mailing list.

    >>> req_id = hold_unsubscription(mlist, 'herb@example.org')
    >>> mlist.send_goodbye_message = False
    >>> handle_unsubscription(mlist, req_id, Action.accept)
    >>> print(mlist.members.get_member('herb@example.org'))
    None


Notifications
=============

Membership change requests
--------------------------

Usually, the list administrators want to be notified when there are membership
change requests they need to moderate.  These notifications are sent when the
list is configured to send them.

    >>> mlist.admin_immed_notify = True

Iris tries to subscribe to the mailing list.

    >>> req_id = hold_subscription(mlist,
    ...     RequestRecord('iris@example.org', 'Iris Person',
    ...                   DeliveryMode.regular, 'en'))

There's now a message in the virgin queue, destined for the list owner.

    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: New subscription request to A Test List from iris@example.org
    From: ant-owner@example.com
    To: ant-owner@example.com
    ...
    Your authorization is required for a mailing list subscription request
    approval:
    <BLANKLINE>
        For:  iris@example.org
        List: ant@example.com

Similarly, the administrator gets notifications on unsubscription requests.
Jeff is a member of the mailing list, and chooses to unsubscribe.

    >>> unsub_req_id = hold_unsubscription(mlist, 'jeff@example.org')
    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: New unsubscription request from A Test List by jeff@example.org
    From: ant-owner@example.com
    To: ant-owner@example.com
    ...
    Your authorization is required for a mailing list unsubscription
    request approval:
    <BLANKLINE>
        By:   jeff@example.org
        From: ant@example.com
    ...


Membership changes
------------------

When a new member request is accepted, the mailing list administrators can
receive a membership change notice.

    >>> mlist.admin_notify_mchanges = True
    >>> mlist.admin_immed_notify = False
    >>> handle_subscription(mlist, req_id, Action.accept)
    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: A Test List subscription notification
    From: noreply@example.com
    To: ant-owner@example.com
    ...
    Iris Person <iris@example.org> has been successfully subscribed to A
    Test List.

Similarly when an unsubscription request is accepted, the administrators can
get a notification.

    >>> req_id = hold_unsubscription(mlist, 'iris@example.org')
    >>> handle_unsubscription(mlist, req_id, Action.accept)
    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: A Test List unsubscription notification
    From: noreply@example.com
    To: ant-owner@example.com
    ...
    Iris Person <iris@example.org> has been removed from A Test List.


Welcome messages
----------------

When a member is subscribed to the mailing list via moderator approval, she
can get a welcome message.

    >>> mlist.admin_notify_mchanges = False
    >>> mlist.send_welcome_message = True
    >>> req_id = hold_subscription(mlist,
    ...     RequestRecord('kate@example.org', 'Kate Person',
    ...                   DeliveryMode.regular, 'en'))
    >>> handle_subscription(mlist, req_id, Action.accept)
    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: Welcome to the "A Test List" mailing list
    From: ant-request@example.com
    To: Kate Person <kate@example.org>
    ...
    Welcome to the "A Test List" mailing list!
    ...


Goodbye messages
----------------

Similarly, when the member's unsubscription request is approved, she'll get a
goodbye message.

    >>> mlist.send_goodbye_message = True
    >>> req_id = hold_unsubscription(mlist, 'kate@example.org')
    >>> handle_unsubscription(mlist, req_id, Action.accept)
    >>> messages = get_queue_messages('virgin')
    >>> len(messages)
    1
    >>> print(messages[0].msg.as_string())
    MIME-Version: 1.0
    ...
    Subject: You have been unsubscribed from the A Test List mailing list
    From: ant-bounces@example.com
    To: kate@example.org
    ...
