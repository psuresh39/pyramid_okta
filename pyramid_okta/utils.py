import okta
import logging
import binascii
import requests
import urlparse

from httplib import OK
from pyramid_okta import settings
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.httpexceptions import HTTPNotFound
from pyramid.httpexceptions import exception_response
from paste.httpheaders import AUTHORIZATION
from okta.framework.OktaError import OktaError as OktaError
from okta.framework.ApiClient import ApiClient


log = logging.getLogger(__name__)

LoginValidationError = 'E0000001'
OktaUserAlreadyActivatedError = 'E0000016'
OktaUserNotFound = 'E0000007'

# ---------------------------

# wrap request methods
def authenticated(func):
    def wrapped(*args, **kwds):
        headers = kwds.get('headers') or {}
        headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'SSWS ' + settings.API_TOKEN
        })

        kwds['headers'] = headers
        response = func(*args, **kwds)
        data = response.json()
        if response.status_code != OK:
            log.error(unicode(data))
            raise exception_response(response.status_code)
        else:
            return data
    return wrapped

get     = authenticated(requests.get)
post    = authenticated(requests.post)
put     = authenticated(requests.put)
delete  = authenticated(requests.delete)

# -----------------------

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
    return post(route('/api/v1/sessions'), json={'sessionToken': session_token})


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

def get_groups(filter='', limit=None, app_id=None):
    """
    Returns the available groups from okta, filtering based on the app id if provided.

    :param app_id:
    :return: [<dict>, ..]
    """
    if app_id is None:
        app_id = settings.APPLICATION_ID

    if app_id:
        url = route('/api/v1/apps/{app}/groups', app=app_id)
    else:
        url = route('/api/v1/groups')

    data = {}
    if limit != None:
        data['limit'] = limit
    if filter:
        data['filter'] = filter

    return get(url, params=data)

def get_group(group_id):
    """
    Returns the okta group for the given group_id.

    :param group_id: <str>
    :return: <dict>
    """
    return get(route('/api/v1/groups/{id}', id=group_id))

def get_user_groups(user_id, app_id=None):
    """
    Return all participating groups of user
    :param user_id: <str>
    :param app_id: <str>
    :return: <list> user groups
    """
    if app_id is None:
        app_id = settings.APPLICATION_ID

    # filter based on an application's associated groups
    if app_id:
        app_groups = get(route('/api/v1/apps/{id}/groups/', id=app_id))
        app_groups = [grp['id'] for grp in app_groups]
    else:
        app_groups = None

    user_groups = get(route('/api/v1/users/{user}/groups', user=user_id))
    groups = []
    for group in user_groups:
        group_id = group['id']
        name = group['profile']['name']
        if app_groups is None or group_id in app_groups:
            groups.append(name)
    return groups


def get_user(user_id, app_id=None):
    """
    Return user profile information
    :param user_id: <str>
    :param app_id: <str> || None
    :return: <dict>
    """
    if app_id is None:
        app_id = settings.APPLICATION_ID

    if app_id:
        url = route('/api/v1/apps/{app}/users/{user}', app=app_id, user=user_id)
    else:
        url = route('/api/v1/users/{user}', user=user_id)

    return get(url)


def route(uri, **kwds):
    """
    Generates a full URL to the okta instance based on the base url from the settings.

    :param uri: <str>
    :param kwds: <kwargs>
    :return: <str>
    """
    return urlparse.urljoin(settings.BASE_URL, uri).format(**kwds)

def delete_user(user_id):
    url = route('/api/v1/users/{user}', user=user_id)
    return delete(url)

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