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

"""Basic WSGI Application object for REST server."""

__all__ = [
    'make_application',
    'make_server',
    ]


import re
import logging

from falcon import API
from falcon.responders import path_not_found
from falcon.routing import create_http_method_map
from mailman.config import config
from mailman.database.transaction import transactional
from mailman.rest.root import Root
from wsgiref.simple_server import WSGIRequestHandler
from wsgiref.simple_server import make_server as wsgi_server


log = logging.getLogger('mailman.http')
_missing = object()
SLASH = '/'



class AdminWebServiceWSGIRequestHandler(WSGIRequestHandler):
    """Handler class which just logs output to the right place."""

    def log_message(self, format, *args):
        """See `BaseHTTPRequestHandler`."""
        log.info('%s - - %s', self.address_string(), format % args)


class RootedAPI(API):
    def __init__(self, root, *args, **kws):
        self._root = root
        super(RootedAPI, self).__init__(*args, **kws)

    @transactional
    def __call__(self, environ, start_response):
        # The only difference between this and the super class's wsgi API is
        # that this wraps a transactional handler around the call.  If an
        # error occurs, the current transaction is aborted, otherwise it is
        # committed.
        return super(RootedAPI, self).__call__(
            environ, start_response)

    def _get_responder(self, req):
        path = req.path
        method = req.method
        path_segments = path.split('/')
        # Since the path is always rooted at /, skip the first segment, which
        # will always be the empty string.
        path_segments.pop(0)
        this_segment = path_segments.pop(0)
        resource = self._root
        while True:
            # See if there's a child matching the current segment.
            # See if any of the resource's child links match the next segment.
            for name in dir(resource):
                if name.startswith('__') and name.endswith('__'):
                    continue
                attribute = getattr(resource, name, _missing)
                assert attribute is not _missing, name
                matcher = getattr(attribute, '__matcher__', _missing)
                if matcher is _missing:
                    continue
                result = None
                if isinstance(matcher, str):
                    # Is the matcher string a regular expression or plain
                    # string?  If it starts with a caret, it's a regexp.
                    if matcher.startswith('^'):
                        cre = re.compile(matcher)
                        # Search against the entire remaining path.
                        tmp_path_segments = path_segments[:]
                        tmp_path_segments.insert(0, this_segment)
                        remaining_path = SLASH.join(tmp_path_segments)
                        mo = cre.match(remaining_path)
                        if mo:
                            result = attribute(
                                req, path_segments, **mo.groupdict())
                    elif matcher == this_segment:
                        result = attribute(req, path_segments)
                else:
                    # The matcher is a callable.  It returns None if it
                    # doesn't match, and if it does, it returns a 3-tuple
                    # containing the positional arguments, the keyword
                    # arguments, and the remaining segments.  The attribute is
                    # then called with these arguments.  Note that the matcher
                    # wants to see the full remaining path components, which
                    # includes the current hop.
                    tmp_path_segments = path_segments[:]
                    tmp_path_segments.insert(0, this_segment)
                    matcher_result = matcher(req, tmp_path_segments)
                    if matcher_result is not None:
                        positional, keyword, path_segments = matcher_result
                        result = attribute(
                            req, path_segments, *positional, **keyword)
                # The attribute could return a 2-tuple giving the resource and
                # remaining path segments, or it could just return the
                # result.  Of course, if the result is None, then the matcher
                # did not match.
                if result is None:
                    continue
                elif isinstance(result, tuple):
                    resource, path_segments = result
                else:
                    resource = result
                # The method could have truncated the remaining segments,
                # meaning, it's consumed all the path segments, or this is the
                # last path segment.  In that case the resource we're left at
                # is the responder.
                if len(path_segments) == 0:
                    # We're at the end of the path, so the root must be the
                    # responder.
                    method_map = create_http_method_map(resource, None, None)
                    responder = method_map[method]
                    return responder, {}, resource
                this_segment = path_segments.pop(0)
                break
            else:
                # None of the attributes matched this path component, so the
                # response is a 404.
                return path_not_found, {}, None



def make_application():
    """Create the WSGI application.

    Use this if you want to integrate Mailman's REST server with your own WSGI
    server.
    """
    return RootedAPI(Root())


def make_server():
    """Create the Mailman REST server.

    Use this if you just want to run Mailman's wsgiref-based REST server.
    """
    host = config.webservice.hostname
    port = int(config.webservice.port)
    server = wsgi_server(
        host, port, make_application(),
        handler_class=AdminWebServiceWSGIRequestHandler)
    return server
