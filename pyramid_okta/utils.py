import base64
import datetime
import okta
import logging

from dateutil import parser as dateutil_parser
from . import settings

from pyramid.httpexceptions import HTTPUnauthorized

log = logging.getLogger(__name__)

def authenticate(username, password):
    auth_client = okta.AuthClient(settings.BASE_URL, settings.API_TOKEN)

    try:
        response = auth_client.authenticate(username, password)
    except Exception as err:
        return {}
    else:
        session_client = okta.SessionsClient(settings.BASE_URL, settings.API_TOKEN)
        session = session_client.create_session_by_session_token(response.sessionToken)

        expires_at = dateutil_parser.parse(response.expiresAt).replace(tzinfo=None)

        output = {
            'access_token': session.id,
            'refresh_token': response.sessionToken,
            'user_id': session.userId,
            'expires_in': (expires_at - datetime.datetime.utcnow()).seconds
        }
        return output

def clear_session(session_id):
    session_client = okta.SessionsClient(settings.BASE_URL, settings.API_TOKEN)

    try:
        response = session_client.clear_session(session_id)
    except Exception as err:
        return False
    else:
        return True

def get_credentials(request):
    """
    Extract the authentication token information.  Supported authentication include:

    * Bearer <token>
    * Basic <client_id>:<client_secret>


    :param request: <pyramid.request.Request>

    :return: <str> token_type, <str> token
    """
    if 'Authorization' in request.headers:
        auth = request.headers.get('Authorization')
    elif 'authorization' in request.headers:
        auth = request.headers.get('authorization')
    else:
        log.debug('no authorization header found.')
        return None, None

    if (not auth.lower().startswith('bearer') and
        not auth.lower().startswith('basic')):
        log.debug('authorization header not of type bearer or basic: %s'
            % auth.lower())
        return None, None

    parts = auth.split()
    if len(parts) != 2:
        return None, None

    token_type = parts[0].lower()
    token = base64.b64decode(parts[1])

    if token_type == 'basic':
        client_id, client_secret = token.split(':')
        if client_id.lower() == 'bearer':
            token_type = 'bearer'
            token = client_secret
        else:
            request.client_id = client_id
            request.client_secret = client_secret

    return token_type, token

def groupfinder(userid, request):
    groups_client = okta.UserGroupsClient(settings.BASE_URL, settings.API_TOKEN)
    pass


def validate_session(session_id):
    session_client = okta.SessionsClient(settings.BASE_URL, settings.API_TOKEN)

    try:
        response = session_client.validate_session(session_id)
    except Exception as err:
        return {}
    else:
        output = {
            'access_token': session_id,
            'user_id': response.userId
        }
        return output