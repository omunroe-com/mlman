============================
Display configuration values
============================

Just like the `Postfix command postconf(1)`_, the ``mailman conf`` command
lets you dump one or more Mailman configuration variables to standard output
or a file.

Mailman's configuration is divided in multiple sections which contain multiple
key-value pairs.  The ``mailman conf`` command allows you to display a
specific key-value pair, or several key-value pairs.

    >>> command = cli('mailman.commands.cli_conf.conf')

To get a list of all key-value pairs of any section, you need to call the
command without any options.

    >>> command('mailman conf')
    [antispam] header_checks:
    ...
    [logging.bounce] level: info
    ...
    [mailman] site_owner: noreply@example.com
    ...

You can list all the key-value pairs of a specific section.

    >>> command('mailman conf --section shell')
    [shell] banner: Welcome to the GNU Mailman shell
    [shell] history_file:
    [shell] prompt: >>>
    [shell] use_ipython: no

You can also pass a key and display all key-value pairs matching the given
key, along with the names of the corresponding sections.

    >>> command('mailman conf --key path')
    [logging.archiver] path: mailman.log
    [logging.bounce] path: bounce.log
    [logging.config] path: mailman.log
    [logging.database] path: mailman.log
    [logging.debug] path: debug.log
    [logging.error] path: mailman.log
    [logging.fromusenet] path: mailman.log
    [logging.http] path: mailman.log
    [logging.locks] path: mailman.log
    [logging.mischief] path: mailman.log
    [logging.plugins] path: plugins.log
    [logging.root] path: mailman.log
    [logging.runner] path: mailman.log
    [logging.smtp] path: smtp.log
    [logging.subscribe] path: mailman.log
    [logging.vette] path: mailman.log

If you specify both a section and a key, you will get the corresponding value.

    >>> command('mailman conf --section mailman --key site_owner')
    noreply@example.com


.. _`Postfix command postconf(1)`: http://www.postfix.org/postconf.1.html
