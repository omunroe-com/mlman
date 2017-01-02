# Copyright (C) 2016 by the Free Software Foundation, Inc.
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

"""Provides support for mocking dnspython calls from dmarc rules and some
organizational domain tests."""

from contextlib import ExitStack
from dns.exception import DNSException
from dns.rdatatype import CNAME, TXT
from dns.resolver import NXDOMAIN, NoAnswer
from mailman.app.lifecycle import create_list
from mailman.interfaces.mailinglist import DMARCMitigateAction
from mailman.rules import dmarc
from mailman.testing.helpers import (
    LogFileMark, specialized_message_from_string as mfs)
from mailman.testing.layers import ConfigLayer
from mailman.utilities.protocols import get as _get
from pkg_resources import resource_filename
from public import public
from unittest import TestCase
from unittest.mock import patch
from urllib.error import URLError


@public
def get_dns_resolver(
        rtype=TXT,
        rdata=b'v=DMARC1; p=reject;',
        rmult=False,
        cmult=False,
        cloop=False):
    """Create a dns.resolver.Resolver mock.

    This is used to return a predictable response to a _dmarc query.  It
    returns p=reject for the example.biz domain and raises an exception for
    other examples.

    It only implements those classes and attributes used by the dmarc rule.
    """
    class Name:
        # mock answer.name
        def __init__(self, name='_dmarc.example.biz.'):
            self.name = name

        def to_text(self):
            return self.name

    class Item:
        # mock answer.items
        def __init__(self, d=rdata, n='_dmarc.example.com.'):
            self.strings = [d]
            # for CNAMES
            self.target = Name(n)

    class Ans_e:
        # mock answer element
        def __init__(
                self,
                typ=rtype,
                d=rdata,
                t='_dmarc.example.com.',
                n='_dmarc.example.biz.'):
            self.rdtype = typ
            self.items = [Item(d, t)]
            self.name = Name(n)

    class Answer:
        # mock answer
        def __init__(self):
            if cloop:
                self.answer = [
                    Ans_e(
                        typ=CNAME,
                        n='_dmarc.example.biz.',
                        t='_dmarc.example.org.'
                        ),
                    Ans_e(
                        typ=CNAME,
                        n='_dmarc.example.org.',
                        t='_dmarc.example.biz.'
                        ),
                    ]
            elif cmult:
                self.answer = [
                    Ans_e(
                        typ=CNAME,
                        n='_dmarc.example.biz.',
                        t='_dmarc.example.net.'
                        ),
                    Ans_e(
                        typ=CNAME,
                        n='_dmarc.example.net.',
                        t='_dmarc.example.com.'
                        ),
                    ]
            elif rmult:
                self.answer = [Ans_e(), Ans_e(d=b'v=DMARC1; p=none;')]
            else:
                self.answer = [Ans_e()]

    class Resolver:
        # mock dns.resolver.Resolver class.
        def __init__(self):
            pass

        def query(self, domain, data_type):
            if data_type != TXT:
                raise NoAnswer
            dparts = domain.split('.')
            if len(dparts) < 3:
                raise NXDOMAIN
            if len(dparts) > 3:
                raise NoAnswer
            if dparts[0] != '_dmarc':
                raise NoAnswer
            if dparts[2] == 'info':
                raise DNSException('no internet')
            if dparts[1] != 'example' or dparts[2] != 'biz':
                raise NXDOMAIN
            self.response = Answer()
            return self
    patcher = patch('dns.resolver.Resolver', Resolver)
    return patcher


@public
def get_org_data():
    """Create a mock to load the organizational domain data from our local
    test data.
    """
    def ourget(url):
        datapath = resource_filename(
            'mailman.rules.tests.data', 'org_domain.txt')
        org_data_url = 'file:///{}'.format(datapath)
        return _get(org_data_url)
    return patch('mailman.rules.dmarc.protocols.get', ourget)


class TestDMARCRules(TestCase):
    """Test organizational domain determination."""

    layer = ConfigLayer

    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        # Make sure every test has a clean cache.
        self.cache = {}
        self.resources.enter_context(
            patch('mailman.rules.dmarc.s_dict', self.cache))

    def test_no_url(self):
        dmarc._get_suffixes(None)
        self.assertEqual(len(self.cache), 0)

    def test_no_data_for_domain(self):
        with get_org_data():
            self.assertEqual(
                dmarc._get_org_dom('sub.dom.example.nxtld'),
                'example.nxtld')

    def test_domain_with_wild_card(self):
        with get_org_data():
            self.assertEqual(
                dmarc._get_org_dom('ssub.sub.foo.kobe.jp'),
                'sub.foo.kobe.jp')

    def test_exception_to_wild_card(self):
        with get_org_data():
            self.assertEqual(
                dmarc._get_org_dom('ssub.sub.city.kobe.jp'),
                'city.kobe.jp')

    def test_no_publicsuffix_dot_org(self):
        mark = LogFileMark('mailman.error')
        with patch('mailman.rules.dmarc.protocols.get',
                   side_effect=URLError('no internet')):
            domain = dmarc._get_org_dom('ssub.sub.city.kobe.jp')
        line = mark.readline()
        self.assertEqual(
            line[-95:],
            'Unable to retrieve data from '
            'https://publicsuffix.org/list/public_suffix_list.dat: '
            'no internet\n')
        self.assertEqual(domain, 'kobe.jp')

    def test_no_at_sign_in_from_address(self):
        # If there's no @ sign in the From: address, the rule can't hit.
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne
To: ant@example.com

""")
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver():
            self.assertFalse(rule.check(mlist, msg, {}))

    def test_dmarc_dns_exception(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.info
To: ant@example.com

""")
        mark = LogFileMark('mailman.error')
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(), get_org_data():
            self.assertFalse(rule.check(mlist, msg, {}))
        line = mark.readline()
        self.assertEqual(
            line[-144:],
            'DNSException: Unable to query DMARC policy for '
            'anne@example.info (_dmarc.example.info). '
            'Abstract base class shared by all dnspython exceptions.\n')

    def test_cname_return(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.biz
To: ant@example.com

""")
        mark = LogFileMark('mailman.error')
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(rtype=CNAME), get_org_data():
            self.assertFalse(rule.check(mlist, msg, {}))
        line = mark.readline()
        self.assertEqual(line, '')

    def test_domain_with_subdomain_policy(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.biz
To: ant@example.com

""")
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(
                rdata=b'v=DMARC1; sp=quarantine;'), get_org_data():
            self.assertFalse(rule.check(mlist, msg, {}))

    def test_org_domain_with_subdomain_policy(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@sub.domain.example.biz
To: ant@example.com

""")
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(
                rdata=b'v=DMARC1; sp=quarantine;'), get_org_data():
            self.assertTrue(rule.check(mlist, msg, {}))

    def test_wrong_dmarc_version(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.biz
To: ant@example.com

""")
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(
                rdata=b'v=DMARC01; p=reject;'), get_org_data():
            self.assertFalse(rule.check(mlist, msg, {}))

    def test_multiple_records(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.biz
To: ant@example.com

""")
        mark = LogFileMark('mailman.error')
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(rmult=True), get_org_data():
            self.assertTrue(rule.check(mlist, msg, {}))
        line = mark.readline()
        self.assertEqual(
            line[-68:],
            'RRset of TXT records for _dmarc.example.biz has 2 v=DMARC1 '
            'entries;\n')

    def test_multiple_cnames(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.biz
To: ant@example.com

""")
        mark = LogFileMark('mailman.error')
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(cmult=True), get_org_data():
            self.assertFalse(rule.check(mlist, msg, {}))
        line = mark.readline()
        self.assertEqual(line, '')

    def test_looping_cnames(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.biz
To: ant@example.com

""")
        mark = LogFileMark('mailman.error')
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(cloop=True), get_org_data():
            self.assertFalse(rule.check(mlist, msg, {}))
        line = mark.readline()
        self.assertEqual(line, '')

    def test_no_policy(self):
        mlist = create_list('ant@example.com')
        # Use action reject.  The rule only hits on reject and discard.
        mlist.dmarc_mitigate_action = DMARCMitigateAction.reject
        msg = mfs("""\
From: anne@example.biz
To: ant@example.com

""")
        rule = dmarc.DMARCMitigation()
        with get_dns_resolver(rdata=b'v=DMARC1; pct=100;'), get_org_data():
            self.assertFalse(rule.check(mlist, msg, {}))
