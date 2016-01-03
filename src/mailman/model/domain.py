# Copyright (C) 2008-2016 by the Free Software Foundation, Inc.
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

"""Domains."""

__all__ = [
    'Domain',
    'DomainManager',
    ]


from mailman.database.model import Model
from mailman.database.transaction import dbconnection
from mailman.interfaces.domain import (
    BadDomainSpecificationError, DomainCreatedEvent, DomainCreatingEvent,
    DomainDeletedEvent, DomainDeletingEvent, IDomain, IDomainManager)
from mailman.interfaces.user import IUser
from mailman.interfaces.usermanager import IUserManager
from mailman.model.mailinglist import MailingList
from urllib.parse import urljoin, urlparse
from sqlalchemy import Column, Integer, Unicode
from sqlalchemy.orm import relationship
from zope.event import notify
from zope.interface import implementer
from zope.component import getUtility



@implementer(IDomain)
class Domain(Model):
    """Domains."""

    __tablename__ = 'domain'

    id = Column(Integer, primary_key=True)

    mail_host = Column(Unicode)
    base_url = Column(Unicode)
    description = Column(Unicode)
    owners = relationship('User',
                          secondary='domain_owner',
                          backref='domains')

    def __init__(self, mail_host,
                 description=None,
                 base_url=None,
                 owners=None):
        """Create and register a domain.

        :param mail_host: The host name for the email interface.
        :type mail_host: string
        :param description: An optional description of the domain.
        :type description: string
        :param base_url: The optional base url for the domain, including
            scheme.  If not given, it will be constructed from the
            `mail_host` using the http protocol.
        :type base_url: string
        :param owners: Optional owners of this domain.
        :type owners: sequence of `IUser` or string emails.
        """
        self.mail_host = mail_host
        self.base_url = (base_url
                         if base_url is not None
                         else 'http://' + mail_host)
        self.description = description
        if owners is not None:
            self.add_owners(owners)

    @property
    def url_host(self):
        """See `IDomain`."""
        return urlparse(self.base_url).netloc

    @property
    def scheme(self):
        """See `IDomain`."""
        return urlparse(self.base_url).scheme

    @property
    @dbconnection
    def mailing_lists(self, store):
        """See `IDomain`."""
        mailing_lists = store.query(MailingList).filter(
            MailingList.mail_host == self.mail_host
            ).order_by(MailingList._list_id)
        for mlist in mailing_lists:
            yield mlist

    def confirm_url(self, token=''):
        """See `IDomain`."""
        return urljoin(self.base_url, 'confirm/' + token)

    def __repr__(self):
        """repr(a_domain)"""
        if self.description is None:
            return ('<Domain {0.mail_host}, base_url: {0.base_url}>').format(
                self)
        else:
            return ('<Domain {0.mail_host}, {0.description}, '
                    'base_url: {0.base_url}>').format(self)

    def add_owner(self, owner):
        """See `IDomain`."""
        user_manager = getUtility(IUserManager)
        if IUser.providedBy(owner):
            user = owner
        else:
            user = user_manager.get_user(owner)
        # BAW 2015-04-06: Make sure this path is tested.
        if user is None:
            user = user_manager.create_user(owner)
        self.owners.append(user)

    def add_owners(self, owners):
        """See `IDomain`."""
        # BAW 2015-04-06: This should probably be more efficient by inlining
        # add_owner().
        for owner in owners:
            self.add_owner(owner)

    def remove_owner(self, owner):
        """See `IDomain`."""
        user_manager = getUtility(IUserManager)
        self.owners.remove(user_manager.get_user(owner))



@implementer(IDomainManager)
class DomainManager:
    """Domain manager."""

    @dbconnection
    def add(self, store,
            mail_host,
            description=None,
            base_url=None,
            owners=None):
        """See `IDomainManager`."""
        # Be sure the mail_host is not already registered.  This is probably
        # a constraint that should (also) be maintained in the database.
        if self.get(mail_host) is not None:
            raise BadDomainSpecificationError(
                'Duplicate email host: %s' % mail_host)
        notify(DomainCreatingEvent(mail_host))
        domain = Domain(mail_host, description, base_url, owners)
        store.add(domain)
        notify(DomainCreatedEvent(domain))
        return domain

    @dbconnection
    def remove(self, store, mail_host):
        domain = self[mail_host]
        notify(DomainDeletingEvent(domain))
        store.delete(domain)
        notify(DomainDeletedEvent(mail_host))
        return domain

    @dbconnection
    def get(self, store, mail_host, default=None):
        """See `IDomainManager`."""
        domains = store.query(Domain).filter_by(mail_host=mail_host)
        if domains.count() < 1:
            return default
        assert domains.count() == 1, (
            'Too many matching domains: %s' % mail_host)
        return domains.one()

    def __getitem__(self, mail_host):
        """See `IDomainManager`."""
        missing = object()
        domain = self.get(mail_host, missing)
        if domain is missing:
            raise KeyError(mail_host)
        return domain

    @dbconnection
    def __len__(self, store):
        return store.query(Domain).count()

    @dbconnection
    def __iter__(self, store):
        """See `IDomainManager`."""
        for domain in store.query(Domain).order_by(Domain.mail_host).all():
            yield domain

    @dbconnection
    def __contains__(self, store, mail_host):
        """See `IDomainManager`."""
        return store.query(Domain).filter_by(mail_host=mail_host).count() > 0
