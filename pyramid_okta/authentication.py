import logging

from zope.interface import implementer
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy

from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPUnauthorized

from . import utils
from .import settings

log = logging.getLogger(__name__)


@implementer(IAuthenticationPolicy)
class OktaAuthenticationPolicy(CallbackAuthenticationPolicy):
    def _get_token(self, request):
        token_type, token = utils.get_credentials(request)

        # authenticate with the username and password
        if token_type == 'basic':
            token_info = utils.authenticate(request.client_id, request.client_secret)
        elif token_type == 'bearer':
            token_info = utils.validate_session(token)
        else:
            raise HTTPBadRequest()

        if not token_info:
            raise HTTPUnauthorized()
        else:
            return token_info

    def remember(self, request, principal, **kw):
        """
        I don't think there is anything to do for an oauth request here.
        """

    def forget(self, request):
        token = self._get_token(request)
        if not token:
            return None
        else:
            utils.clear_session(token['access_token'])

    def authenticated_userid(self, request):
        token = self._get_token(request)
        if not token:
            return None
        return token.get('user_id')

