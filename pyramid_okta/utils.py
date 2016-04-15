import okta
import logging
import binascii
import requests

from httplib import OK
from pyramid_okta import settings
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.httpexceptions import HTTPNotFound
from paste.httpheaders import AUTHORIZATION
from okta.framework.OktaError import OktaError as OktaError
from okta.framework.ApiClient import ApiClient


log = logging.getLogger(__name__)

LoginValidationError = 'E0000001'
OktaUserAlreadyActivatedError = 'E0000016'
OktaUserNotFound = 'E0000007'


def parse_auth_header(request):
    """
    Parse HTTP auth headers
    :param request: <pyramid_request>
    :return: <tuple> auth method and auth credentials
    """
    authorization = AUTHORIZATION(request.environ)
    try:
        authmethod, auth = authorization.split(' ', 1)
        return authmethod.lower(), auth
    except ValueError:  # not enough values to unpack
        raise HTTPBadRequest()


def get_basic_auth_credentials(auth):
    """
    Used to get basic auth credentials
    :param auth: <str> base64 encoded string
    :return: <dict>
    """
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


def get_bearer_auth_credentials(auth):
    """
    Used to get credentials from bearer auth
    :param auth: <str>
    :return: <dict>
    """
    try:
        session_token = auth.strip()
    except binascii.Error:  # can't decode
        raise HTTPBadRequest()
    try:
        session = validate_session(session_token)
    except OktaError:
        return None
    return {
        'client_id': session['user_id'],
        'client_secret': None,
        'access_token': session_token
    }


def get_credentials(request):
    """
    Parse Authorization HTTP header and return credentials
    :param request: <pyramid.request>
    :return: <dict> containing client_id and client_secret
    """
    authmethod, auth = parse_auth_header(request)
    if authmethod.lower() == 'basic':
        return get_basic_auth_credentials(auth)
    elif authmethod.lower() == 'bearer':
        return get_bearer_auth_credentials(auth)
    else:
        raise HTTPUnauthorized()


def basic_auth(credentials):
    """
    Perform basic auth
    :param credentials: <dict>
    :return: <dict>
    """
    auth_client = okta.AuthClient(settings.BASE_URL, settings.API_TOKEN)
    try:
        response = auth_client.authenticate(
            credentials['client_id'],
            credentials['client_secret']
        )
    except OktaError:
        return None
    else:
        output = dict()
        output['user'] = response.embedded.user.__dict__
        output['access_token'] = response.sessionToken
        return output


def bearer_auth(credentials):
    """
    Perform Bearer auth
    :param credentials: <dict>
    :return: <okta.models.Session>
    """
    try:
        session = validate_session(credentials['access_token'])
    except OktaError:
        return None
    else:
        return session


def authenticate(credentials, request):
    """
    Authenticate credentials against Okta
    :param credentials: <dict>
    :param request: <pyramid.request>
    :return: <list> principals representing requesting user
    """
    authmethod, auth = parse_auth_header(request)
    if authmethod.lower() == 'basic':
        response = basic_auth(credentials)
        if response:
            groups = get_user_groups(response['user']['id'])
            groups.append(response['user']['id'])
            return groups
    elif authmethod.lower() == 'bearer':
        session = bearer_auth(credentials)
        if session:
            # set request access_token
            request.okta_extras.set_access_token(session['access_token'])
            groups = get_user_groups(session['user_id'])
            groups.append(session['user_id'])
            return groups


def create_session_by_session_token(session_token):
    """
    Create Session by session token
    :param session_token: <str>
    :return: <dict>
    """
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'SSWS ' + settings.API_TOKEN
    }

    response = requests.post(
        settings.BASE_URL + '/api/v1/sessions',
        json={'sessionToken': session_token},
        headers=headers
    )
    if response.status_code == OK:
        return response.json()
    else:
        return None


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


def get_user(user_id):
    """
    Return user profile information
    :param user_id: <str>
    :return: <dict>
    """
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'SSWS ' + settings.API_TOKEN
    }

    response = requests.get(
        settings.BASE_URL + '/api/v1/users/' + user_id,
        headers=headers
    )

    user = response.json()
    if 'errorId' in user:
        raise HTTPNotFound()
    else:
        return user


def delete_user(user_id):
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'SSWS ' + settings.API_TOKEN
    }

    response = requests.delete(
        settings.BASE_URL + '/api/v1/users/' + user_id,
        headers=headers
    )


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