# Copyright (C) 2007-2018 by the Free Software Foundation, Inc.
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

import re
import sys

from setuptools import setup, find_packages
from string import Template


if sys.hexversion < 0x30500f0:
    print('Mailman requires at least Python 3.5')
    sys.exit(1)


# Calculate the version number without importing the mailman package.
with open('src/mailman/version.py') as fp:
    for line in fp:
        mo = re.match("VERSION = '(?P<version>[^']+?)'", line)
        if mo:
            __version__ = mo.group('version')
            break
    else:
        print('No version number found')
        sys.exit(1)



# Ensure that all the .mo files are generated from the corresponding .po file.
# This procedure needs to be made sane, probably when the language packs are
# properly split out.

# Create the .mo files from the .po files.  There may be errors and warnings
# here and that could cause the digester.txt test to fail.
## start_dir = os.path.dirname('src/mailman/messages')
## for dirpath, dirnames, filenames in os.walk(start_dir):
##     for filename in filenames:
##         po_file = os.path.join(dirpath, filename)
##         basename, ext = os.path.splitext(po_file)
##         if ext <> '.po':
##             continue
##         mo_file = basename + '.mo'
##         if (not os.path.exists(mo_file) or
##             os.path.getmtime(po_file) > os.path.getmtime(mo_file)):
##             # The mo file doesn't exist or is older than the po file.
##             os.system('msgfmt -o %s %s' % (mo_file, po_file))



# XXX The 'bin/' prefix here should be configurable.
template = Template('$script = mailman.bin.$script:main')
scripts = set(
    template.substitute(script=script)
    for script in ('mailman', 'runner', 'master')
    )



setup(
    name            = 'mailman',
    version         = __version__,
    description     = 'Mailman -- the GNU mailing list manager',
    long_description= """\
This is GNU Mailman, a mailing list management system distributed under the
terms of the GNU General Public License (GPL) version 3 or later.  The name of
this software is spelled 'Mailman' with a leading capital 'M' but with a lower
case second `m'.  Any other spelling is incorrect.""",
    author          = 'The Mailman Developers',
    author_email    = 'mailman-developers@python.org',
    license         = 'GPLv3',
    url             = 'http://www.list.org',
    keywords        = 'email',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: '
            'GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Communications :: Email :: Mailing List Servers',
        'Topic :: Communications :: Usenet News',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        ],
    packages        = find_packages('src'),
    package_dir     = {'': 'src'},
    include_package_data = True,
    entry_points    = {
        'console_scripts' : list(scripts),
        },
    install_requires = [
        'aiosmtpd>=1.1',
        'alembic',
        'atpublic',
        'click>=7.0',
        'dnspython>=1.14.0',
        'falcon>=1.0.0rc1',
        'flufl.bounce',
        'flufl.i18n>=2.0',
        'flufl.lock>=3.1',
        'lazr.config',
        'passlib',
        'requests',
        'sqlalchemy>=1.2.3',
        'zope.component',
        'zope.configuration',
        'zope.event',
        'zope.interface',
        ],
    )

# flake8: noqa
