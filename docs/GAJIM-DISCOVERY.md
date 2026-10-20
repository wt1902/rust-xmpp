# Gajim discovery verification — 0.7.1

Upstream sources read 2026-10-20 (mutable master, not pinned):

- https://raw.githubusercontent.com/gajim/gajim/master/src/gajim/common/modules/security_labels.py
- https://raw.githubusercontent.com/gajim/gajim/master/src/gajim/common/modules/register.py
- https://raw.githubusercontent.com/gajim/gajim/master/src/gajim/gtk/preference/server_info.py
- https://raw.githubusercontent.com/gajim/python-nbxmpp/master/nbxmpp/modules/security_labels.py
- https://xmpp.org/extensions/xep-0258.html
- https://xmpp.org/extensions/xep-0077.html

Gajim sets SecLabels.supported from sec-label:0 in info.features and Register.supported
from jabber:iq:register. The server-info window uses those values, not only the
pre-auth registration stream feature. nbxmpp catalog queries use catalog:2 with
@to; server replies preserve the target attribute.

Server now advertises sec-label:0/catalog:2/catalog:0 on domain and current account
security features on own bare JID. Registration discovery is gated by register,
whereas creating a new account remains gated by allow_registration.

Tests exercise real TLS account management and catalogs, enabled/disabled modules,
registration gate, password login after change and rejection after cancellation.
The sample policy schema is a catalog metadata adapter only. Names classify labels;
they confer no access or enforcement. Unknown policy fields fail explicitly.
