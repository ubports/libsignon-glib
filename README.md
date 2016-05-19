Single signon authentication library for GLib applications
==========================================================

This project is a library for managing single signon credentilas which can be
used from GLib applications. It is effectively a GLib binding for the D-Bus API
provided by [signond][].
It is part of the accounts-sso project:

https://gitlab.com/groups/accounts-sso

Dependencies
------------

The project depends on GLib (including GIO and GObject), [signond][] and [check][].

Licence
-------

The library is licensed under the GNU LGPL version 2.1.

Resources
---------

[API reference documentation](http://accounts-sso.gitlab.io/libsignon-glib/)

[Official source code repository](https://gitlab.com/accounts-sso/libsignon-glib)

[signond]: https://gitlab.com/accounts-sso/signond
[check]: https://github.com/libcheck/check
