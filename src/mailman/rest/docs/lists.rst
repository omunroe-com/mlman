=============
Mailing lists
=============

The REST API can be queried for the set of known mailing lists.  There is a
top level collection that can return all the mailing lists.  There aren't any
yet though.

    >>> dump_json('http://localhost:9001/3.0/lists')
    http_etag: "..."
    start: 0
    total_size: 0

Create a mailing list in a domain and it's accessible via the API.
::

    >>> mlist = create_list('ant@example.com')
    >>> transaction.commit()

    >>> dump_json('http://localhost:9001/3.0/lists')
    entry 0:
        display_name: Ant
        fqdn_listname: ant@example.com
        http_etag: "..."
        list_id: ant.example.com
        list_name: ant
        mail_host: example.com
        member_count: 0
        self_link: http://localhost:9001/3.0/lists/ant.example.com
        volume: 1
    http_etag: "..."
    start: 0
    total_size: 1

You can also query for lists from a particular domain.

    >>> dump_json('http://localhost:9001/3.0/domains/example.com/lists')
    entry 0:
        display_name: Ant
        fqdn_listname: ant@example.com
        http_etag: "..."
        list_id: ant.example.com
        list_name: ant
        mail_host: example.com
        member_count: 0
        self_link: http://localhost:9001/3.0/lists/ant.example.com
        volume: 1
    http_etag: "..."
    start: 0
    total_size: 1


Paginating over list records
----------------------------

Instead of returning all the list records at once, it's possible to return
them in pages by adding the GET parameters ``count`` and ``page`` to the
request URI.  Page 1 is the first page and ``count`` defines the size of the
page.
::

    >>> mlist = create_list('bird@example.com')
    >>> transaction.commit()

    >>> dump_json('http://localhost:9001/3.0/domains/example.com/lists'
    ...           '?count=1&page=1')
    entry 0:
        display_name: Ant
        fqdn_listname: ant@example.com
        http_etag: "..."
        list_id: ant.example.com
        list_name: ant
        mail_host: example.com
        member_count: 0
        self_link: http://localhost:9001/3.0/lists/ant.example.com
        volume: 1
    http_etag: "..."
    start: 0
    total_size: 2

    >>> dump_json('http://localhost:9001/3.0/domains/example.com/lists'
    ...           '?count=1&page=2')
    entry 0:
        display_name: Bird
        fqdn_listname: bird@example.com
        http_etag: "..."
        list_id: bird.example.com
        list_name: bird
        mail_host: example.com
        member_count: 0
        self_link: http://localhost:9001/3.0/lists/bird.example.com
        volume: 1
    http_etag: "..."
    start: 1
    total_size: 2


Creating lists via the API
==========================

New mailing lists can also be created through the API, by posting to the
``lists`` URL.

    >>> dump_json('http://localhost:9001/3.0/lists', {
    ...           'fqdn_listname': 'bee@example.com',
    ...           })
    content-length: 0
    date: ...
    location: http://localhost:9001/3.0/lists/bee.example.com
    ...

The mailing list exists in the database.
::

    >>> from mailman.interfaces.listmanager import IListManager
    >>> from zope.component import getUtility
    >>> list_manager = getUtility(IListManager)

    >>> bee = list_manager.get('bee@example.com')
    >>> bee
    <mailing list "bee@example.com" at ...>

The mailing list was created using the default style, which allows list posts.

    >>> bee.allow_list_posts
    True

.. Abort the Storm transaction.
    >>> transaction.abort()

It is also available in the REST API via the location given in the response.

    >>> dump_json('http://localhost:9001/3.0/lists/bee.example.com')
    display_name: Bee
    fqdn_listname: bee@example.com
    http_etag: "..."
    list_id: bee.example.com
    list_name: bee
    mail_host: example.com
    member_count: 0
    self_link: http://localhost:9001/3.0/lists/bee.example.com
    volume: 1

Normally, you access the list via its RFC 2369 list-id as shown above, but for
backward compatibility purposes, you can also access it via the list's posting
address, if that has never been changed (since the list-id is immutable, but
the posting address is not).

    >>> dump_json('http://localhost:9001/3.0/lists/bee@example.com')
    display_name: Bee
    fqdn_listname: bee@example.com
    http_etag: "..."
    list_id: bee.example.com
    list_name: bee
    mail_host: example.com
    member_count: 0
    self_link: http://localhost:9001/3.0/lists/bee.example.com
    volume: 1


Apply a style at list creation time
-----------------------------------

:ref:`List styles <list-styles>` allow you to more easily create mailing lists
of a particular type, e.g. discussion lists.  We can see which styles are
available, and which is the default style.

    >>> dump_json('http://localhost:9001/3.0/lists/styles')
    default: legacy-default
    http_etag: "..."
    style_names: ['legacy-announce', 'legacy-default']

When creating a list, if we don't specify a style to apply, the default style
is used.  However, we can provide a style name in the POST data to choose a
different style.

    >>> dump_json('http://localhost:9001/3.0/lists', {
    ...           'fqdn_listname': 'cat@example.com',
    ...           'style_name': 'legacy-announce',
    ...           })
    content-length: 0
    date: ...
    location: http://localhost:9001/3.0/lists/cat.example.com
    ...

We can tell that the list was created using the `legacy-announce` style,
because announce lists don't allow posting by the general public.

    >>> cat = list_manager.get('cat@example.com')
    >>> cat.allow_list_posts
    False

.. Abort the Storm transaction.
    >>> transaction.abort()


Deleting lists via the API
==========================

Existing mailing lists can be deleted through the API, by doing an HTTP
``DELETE`` on the mailing list URL.
::

    >>> dump_json('http://localhost:9001/3.0/lists/bee.example.com',
    ...           method='DELETE')
    content-length: 0
    date: ...
    server: ...
    status: 204

The mailing list does not exist.

    >>> print(list_manager.get('bee@example.com'))
    None

.. Abort the Storm transaction.
    >>> transaction.abort()

For backward compatibility purposes, you can delete a list via its posting
address as well.

    >>> dump_json('http://localhost:9001/3.0/lists/ant@example.com',
    ...           method='DELETE')
    content-length: 0
    date: ...
    server: ...
    status: 204

The mailing list does not exist.

    >>> print(list_manager.get('ant@example.com'))
    None


Managing mailing list archivers
===============================

The Mailman system has some site-wide enabled archivers, and each mailing list
can enable or disable these archivers individually.  This gives list owners
control over where traffic to their list is archived.  You can see which
archivers are available, and whether they are enabled for this mailing list.
::

    >>> mlist = create_list('dog@example.com')
    >>> transaction.commit()

    >>> dump_json('http://localhost:9001/3.0/lists/dog@example.com/archivers')
    http_etag: "..."
    mail-archive: True
    mhonarc: True
    prototype: True

You can set all the archiver states by putting new state flags on the
resource.
::

    >>> dump_json(
    ...     'http://localhost:9001/3.0/lists/dog@example.com/archivers', {
    ...         'mail-archive': False,
    ...         'mhonarc': True,
    ...         'prototype': False,
    ...         }, method='PUT')
    content-length: 0
    date: ...
    server: ...
    status: 204

    >>> dump_json('http://localhost:9001/3.0/lists/dog@example.com/archivers')
    http_etag: "..."
    mail-archive: False
    mhonarc: True
    prototype: False

You can change the state of a subset of the list archivers.
::

    >>> dump_json(
    ...     'http://localhost:9001/3.0/lists/dog@example.com/archivers', {
    ...         'mhonarc': False,
    ...         }, method='PATCH')
    content-length: 0
    date: ...
    server: ...
    status: 204

    >>> dump_json('http://localhost:9001/3.0/lists/dog@example.com/archivers')
    http_etag: "..."
    mail-archive: False
    mhonarc: False
    prototype: False
