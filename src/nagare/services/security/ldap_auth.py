# Encoding: utf-8

# --
# Copyright (c) 2008-2024 Net-ng.
# All rights reserved.
#
# This software is licensed under the BSD License, as described in
# the file LICENSE.txt, which you should have received as part of
# this distribution.
# --

import ldap

from nagare.services.security import form_auth


class Authentication(form_auth.Authentication):
    CONFIG_SPEC = dict(
        form_auth.Authentication.CONFIG_SPEC,
        host='string(default="127.0.0.1", help="LDAP server hostname")',
        port='integer(default={}, help="server port")'.format(ldap.PORT),
        revalidate='boolean(default=True)',
        user_dn='string(help="dn with `{uid}` placeholder")',
        user_filter='string(default=None)',
        user_attrs='string_list(default=list())',
        timeout='integer(default=-1, help="communication timeout")',
    )

    def __init__(
        self,
        name,
        dist,
        host,
        port,
        revalidate,
        user_dn,
        user_filter,
        user_attrs,
        timeout,
        services_service,
        **config,
    ):
        services_service(
            super(Authentication, self).__init__,
            name,
            dist,
            **config,
        )
        if not revalidate and not self.encrypted:
            raise ValueError('Incompatible values for parameters `revalidate` and `[[cookie]] / encrypt`')

        self.host = host
        self.port = port
        self.revalidate = revalidate
        self.user_dn = user_dn
        self.user_filter = user_filter
        self.user_attrs = user_attrs
        self.timeout = timeout

    @staticmethod
    def create_connection(host, port):
        return ldap.initialize(f'ldap://{host}:{port}')

    @staticmethod
    def filter_credentials(credentials, to_keep):
        return {k: v for k, v in credentials.items() if k in to_keep}

    def to_cookie(self, principal, **credentials):
        return super(Authentication, self).to_cookie(
            principal,
            _auth=int(not self.revalidate),
            **self.filter_credentials(credentials, {'password'}),
        )

    def retrieve_credentials(self, uid, password):
        credentials = {}

        user_dn = self.user_dn.format(uid=uid)
        connection = self.create_connection(self.host, self.port)
        try:
            connection.simple_bind_s(user_dn, password.encode('UTF-8'))
        except ldap.INVALID_CREDENTIALS:
            pass
        except ldap.LDAPError as e:
            self.logger.critical(e.args[0].get('desc', 'LDAP Error'))
        else:
            search_result = connection.search_st(
                user_dn,
                ldap.SCOPE_BASE,
                self.user_filter,
                (self.user_attrs + ['uid']) if self.user_attrs else [],
                False,
                self.timeout,
            )
            if search_result:
                credentials = search_result[0][1]
        finally:
            connection.unbind()

        return credentials

    def get_principal(self, request, **params):
        principal, credentials, response = super(Authentication, self).get_principal(request, **params)

        password = credentials.get('password')
        revalidate = not credentials.pop('_auth', False)

        if principal and revalidate:
            if password:
                credentials = self.retrieve_credentials(principal, password)
                credentials['password'] = password

            if not credentials.pop('uid', False):
                principal = None

        return principal, credentials, response
