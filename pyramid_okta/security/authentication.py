""" Defines Remote authentication scheme. """

__authors__ = ['Eric Hulser', 'Pranay Suresh']
__author__ = ', '.join(__authors__)
__email__ = 'toolbox@teslamotors.com'
__copyright__ = 'Copyright Tesla Motors Inc. 2016'


import logging

from pyramid.security import Everyone
from pyramid.security import Authenticated
from pyramid_okta import utils

log = logging.getLogger(__name__)


class OktaAuthenticationPolicy(object):
    """ A :app:`Pyramid` :term:`authentication policy` which
    obtains data from basic authentication headers.

    Constructor Arguments

    ``check``

        A callback passed the credentials and the request,
        expected to return list of principals corresponding to user. Required.

    ``realm``

        Default: ``Realm``.  The Basic Auth realm string.
    """

    def __init__(self, check=utils.authenticate, realm='Realm'):
        self.check = check
        self.realm = realm

    def authenticated_userid(self, request):
        """
        Return user_id for authenticated user after checking with Okta
        :param request: <pyramid.request>
        :return: <str> user_id
        """
        credentials = utils.get_credentials(request)
        if credentials is None:
            return None
        user_id = credentials['client_id']
        if self.check(credentials, request) is not None:
            return user_id

    def effective_principals(self, request):
        """
        Return all the groups user belongs to
        :param request: <pyramid.request>
        :return: <list> group names
        """
        effective_principals = [Everyone]
        credentials = utils.get_credentials(request)
        if credentials is None:
            return effective_principals
        user_id = credentials['client_id']
        groups = self.check(credentials, request)
        if groups is None:
            effective_principals.append(user_id)
        else:
            effective_principals.append(Authenticated)
            effective_principals.append('login_required')
            effective_principals.extend(groups)
        return effective_principals

    def unauthenticated_userid(self, request):
        """
        Return user_id based on request, without checking in Okta
        :param request: <pyramid.request>
        :return: user_id
        """
        credentials = utils.get_credentials(request)
        if credentials is None:
            return None
        user_id = credentials['client_id']
        return user_id
