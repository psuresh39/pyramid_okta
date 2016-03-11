import okta
import projex.rest
import logging
import binascii

from . import settings
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPUnauthorized
from paste.httpheaders import AUTHORIZATION
from okta.framework.OktaError import OktaError
from okta.framework.ApiClient import ApiClient


log = logging.getLogger(__name__)


def get_credentials(request):
    """
    Parse Authorization HTTP header and return credentials
    :param request: <pyramid.request>
    :return: <dict> containing client_id and client_secret
    """
    authorization = AUTHORIZATION(request.environ)
    try:
        authmethod, auth = authorization.split(' ', 1)
    except ValueError:  # not enough values to unpack
        raise HTTPBadRequest()

    if authmethod.lower() == 'basic':
        try:
            auth = auth.strip().decode('base64')
        except binascii.Error:  # can't decode
            raise HTTPBadRequest()
        try:
            client_id, client_secret = auth.split(':', 1)
        except ValueError:  # not enough values to unpack
            raise HTTPBadRequest()
        return {
            'client_id': client_id,
            'client_secret': client_secret
        }
    elif authmethod.lower() == 'bearer':
        try:
            session_token = auth.strip()
        except binascii.Error:  # can't decode
            raise HTTPBadRequest()
        session = validate_session(session_token)
        return {
            'client_id': session['user_id'],
            'client_secret': None
        }
    else:
        raise HTTPUnauthorized()


def authenticate(credentials, request):
    """
    Authenticate credentials against Okta
    :param credentials: <dict>
    :param request: <pyramid.request>
    :return: <list> principals representing requesting user
    """
    authorization = AUTHORIZATION(request.environ)
    try:
        authmethod, auth = authorization.split(' ', 1)
    except ValueError:  # not enough values to unpack
        raise HTTPBadRequest()

    if authmethod.lower() == 'basic':
        auth_client = okta.AuthClient(settings.BASE_URL, settings.API_TOKEN)
        try:
            response = auth_client.authenticate(
                credentials['client_id'],
                credentials['client_secret']
            )
        except OktaError:
            return None
        else:
            return get_user_groups(response['_embedded']['user']['id'])
    elif authmethod.lower() == 'bearer':
        try:
            session = validate_session(credentials['client_id'])
        except OktaError:
            return None
        else:
            return get_user_groups(session['user_id'])


def clear_session(session_id):
    """
    Clear session at Okta
    :param session_id: <str>
    :return: <bool>
    """
    session_client = okta.SessionsClient(settings.BASE_URL, settings.API_TOKEN)
    try:
        _ = session_client.clear_session(session_id)
    except OktaError:
        return False
    else:
        return True


def get_user_groups(user_id):
    """
    Return all participating groups of user
    :param user_id: <str>
    :return: <list> user groups
    """
    user_client = okta.UsersClient(settings.BASE_URL, settings.API_TOKEN)
    try:
        response = ApiClient.get_path(user_client, '/{0}/groups'.format(user_id))
    except OktaError:
        return []
    else:
        groups = []
        for group in response.json():
            groups.append(group['profile']['name'])
        return groups


def get_user_profile(user_id):
    """
    Return user profile information
    :param user_id: <str>
    :return: <dict>
    """
    user_client = okta.UsersClient(settings.BASE_URL, settings.API_TOKEN)
    try:
        response = user_client.get_path('/{0}'.format(user_id))     # built-in get user strips out profile info
    except OktaError:
        return {}
    else:
        content = projex.rest.unjsonify(response.content)
        return content.get('profile')


def validate_session(session_id):
    """
    Validate session token
    :param session_id: <str>
    :return: <dict>
    """
    session_client = okta.SessionsClient(settings.BASE_URL, settings.API_TOKEN)
    try:
        response = session_client.validate_session(session_id)
    except OktaError:
        raise
    else:
        output = {
            'access_token': session_id,
            'user_id': response.userId
        }
        return output