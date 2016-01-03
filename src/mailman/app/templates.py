# Copyright (C) 2012-2016 by the Free Software Foundation, Inc.
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

"""Template loader."""

__all__ = [
    'TemplateLoader',
    ]


from contextlib import closing
from mailman.interfaces.languages import ILanguageManager
from mailman.interfaces.listmanager import IListManager
from mailman.interfaces.templates import ITemplateLoader
from mailman.utilities.i18n import TemplateNotFoundError, find
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import BaseHandler, build_opener, install_opener, urlopen
from urllib.response import addinfourl
from zope.component import getUtility
from zope.interface import implementer



class MailmanHandler(BaseHandler):
    # Handle internal mailman: URLs.
    def mailman_open(self, req):
        # Parse urls of the form:
        #
        # mailman:///<fqdn_listname>/<language>/<template_name>
        #
        # where only the template name is required.
        mlist = code = template = None
        # Parse the full requested URL and be sure it's something we handle.
        original_url = req.get_full_url()
        parsed = urlparse(original_url)
        assert parsed.scheme == 'mailman'
        # The path can contain one, two, or three components.  Since no empty
        # path components are legal, filter them out.
        parts = [p for p in parsed.path.split('/') if p]
        if len(parts) == 0:
            raise URLError('No template specified')
        elif len(parts) == 1:
            template = parts[0]
        elif len(parts) == 2:
            part0, template = parts
            # Is part0 a language code or a mailing list?  It better be one or
            # the other, and there's no possibility of namespace collisions
            # because language codes don't contain @ and mailing list names
            # MUST contain @.
            language = getUtility(ILanguageManager).get(part0)
            mlist = getUtility(IListManager).get(part0)
            if language is None and mlist is None:
                raise URLError('Bad language or list name')
            elif mlist is None:
                code = language.code
        elif len(parts) == 3:
            fqdn_listname, code, template = parts
            mlist = getUtility(IListManager).get(fqdn_listname)
            if mlist is None:
                raise URLError('Missing list')
            language = getUtility(ILanguageManager).get(code)
            if language is None:
                raise URLError('No such language')
            code = language.code
        else:
            raise URLError('No such file')
        # Find the template, mutating any missing template exception.
        try:
            path, fp = find(template, mlist, code)
        except TemplateNotFoundError:
            raise URLError('No such file')
        return addinfourl(fp, {}, original_url)



@implementer(ITemplateLoader)
class TemplateLoader:
    """Loader of templates, with caching and support for mailman:// URIs."""

    def __init__(self):
        opener = build_opener(MailmanHandler())
        install_opener(opener)

    def get(self, uri):
        """See `ITemplateLoader`."""
        with closing(urlopen(uri)) as fp:
            return fp.read()
