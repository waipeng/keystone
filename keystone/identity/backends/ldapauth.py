"""
Allows only authentication the Active Directory LDAP servers.
Tenant management, etc, are still stored in SQL database
"""

from __future__ import absolute_import
from keystone import config
from keystone.common import ldap as common_ldap
from keystone.common import logging
from . import sql

import ldap

CONF = config.CONF
LOG = logging.getLogger(__name__)

# set this to false if you don't want to fallback to sql auth
FALLBACK = CONF.ldapauth.fallback

class Identity(sql.Identity):
    def __init__(self):
        super(Identity, self).__init__()
        self.ldaphosts = []
        self.ldaphosts.append(CONF.ldapauth.server1_host)
        self.ldaphosts.append(CONF.ldapauth.server2_host)
        self.ldaphosts.append(CONF.ldapauth.server3_host)
        self.ldapdomains = []
        self.ldapdomains.append(CONF.ldapauth.server1_domain)
        self.ldapdomains.append(CONF.ldapauth.server2_domain)
        self.ldapdomains.append(CONF.ldapauth.server3_domain)

    def _check_password(self, password, user_ref):
        username = user_ref.get('name')

        if (username in ['admin', 'nova', 'swift', 'glance', 'useradmin']):
            return super(Identity, self)._check_password(password, user_ref)

        for i in range(len(self.ldaphosts)):
            if self.ldaphosts[i] is not None:
                try:
                    ldaphost = self.ldaphosts[i]
                    ldapuser = username
                    if self.ldapdomains[i] is not None:
                        ldapuser = self.ldapdomains[i]+"\\"+username
                    LOG.debug("Looking up "+ldaphost+" for "+ldapuser)
                    l = ldap.initialize(ldaphost)
                    ldap.protocol_version = 3
                    l.simple_bind_s(ldapuser, password)
                    return True
                except Exception:
                    LOG.debug("Unable to bind to "+ldaphost)

        LOG.debug("Unable to bind to all servers. Giving up.")
        if FALLBACK:
            return super(Identity, self)._check_password(password, user_ref)
        else:
            return False

# vim:tabstop=4:shiftwidth=4:smartindent:expandtab
