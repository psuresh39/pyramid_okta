__author__ = 'psuresh'

from pyramid.interfaces import ISession
from pyramid.compat import PY3, pickle
from pyramid.session import manage_changed
from zope.interface import implementer
import time
import dateutil.parser
import requests
from pyramid_okta.utils import clear_session
from pyramid_okta.utils import OktaError


def manage_accessed(wrapped):
    """ Decorator which causes a cookie to be renewed when an accessor
    method is called."""
    def accessed(session, *arg, **kw):
        return wrapped(session, *arg, **kw)
    accessed.__doc__ = wrapped.__doc__
    return accessed


def OktaSessionFactory(
        okta_base_url='',
        okta_api_token='',
        cookie_name='okta_session',
        max_age=None,
        path='/',
        domain=None,
        secure=False,
        httponly=False
        ):

    @implementer(ISession)
    class OktaSession(dict):
        """ Dictionary-like session object, based on CookieSession """

        # configuration parameters
        _okta_base_url = okta_base_url
        _okta_api_token = okta_api_token
        _cookie_name = cookie_name
        _cookie_max_age = max_age
        _cookie_path = path
        _cookie_domain = domain
        _cookie_secure = secure
        _cookie_httponly = httponly

        # dirty flag
        _dirty = False

        def __init__(self, request):
            self.request = request
            now = time.time()
            expires = renewed = now
            new = True
            value = None
            state = {}
            cookieval = self._get_cookie()
            if cookieval:
                headers = {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'Authorization': 'SSWS ' + self._okta_api_token
                }

                response = requests.get(
                    self._okta_base_url + '/api/v1/sessions/' + cookieval,
                    headers=headers
                )
                if response.status_code == 200:
                    value = response.json()

            if value is not None:
                try:
                    renewed = float(time.mktime(dateutil.parser.parse(
                        value['lastPasswordVerification']
                    ).timetuple()))

                    expires = float(time.mktime(dateutil.parser.parse(
                        value['expiresAt']
                    ).timetuple()))

                    state = value
                    new = False
                except (TypeError, ValueError):
                    # value failed to unpack properly or renewed was not
                    # a numeric type so we'll fail deserialization here
                    state = {}

            if now > expires:
                # expire the session because it was not renewed
                # before the timeout threshold
                state = {}

            self.expires = expires
            self.renewed = renewed
            self.new = new
            dict.__init__(self, state)

        # ISession methods
        def changed(self):
            if not self._dirty:
                self._dirty = True

                def set_cookie_callback(request, response):
                    self._set_cookie(response)
                    self.request = None  # explicitly break cycle for gc
                self.request.add_response_callback(set_cookie_callback)

        def invalidate(self):
            cookieval = self._get_cookie()
            if cookieval:
                try:
                    clear_session(cookieval)
                except OktaError:
                    return False
                else:
                    self.clear()
                    return True
            else:
                return False

        # non-modifying dictionary methods
        get = manage_accessed(dict.get)
        __getitem__ = manage_accessed(dict.__getitem__)
        items = manage_accessed(dict.items)
        values = manage_accessed(dict.values)
        keys = manage_accessed(dict.keys)
        __contains__ = manage_accessed(dict.__contains__)
        __len__ = manage_accessed(dict.__len__)
        __iter__ = manage_accessed(dict.__iter__)

        if not PY3:
            iteritems = manage_accessed(dict.iteritems)
            itervalues = manage_accessed(dict.itervalues)
            iterkeys = manage_accessed(dict.iterkeys)
            has_key = manage_accessed(dict.has_key)

        # modifying dictionary methods
        clear = manage_changed(dict.clear)
        update = manage_changed(dict.update)
        setdefault = manage_changed(dict.setdefault)
        pop = manage_changed(dict.pop)
        popitem = manage_changed(dict.popitem)
        __setitem__ = manage_changed(dict.__setitem__)
        __delitem__ = manage_changed(dict.__delitem__)

        # flash API methods
        @manage_changed
        def flash(self, msg, queue='', allow_duplicate=True):
            storage = self.setdefault('_f_' + queue, [])
            if allow_duplicate or (msg not in storage):
                storage.append(msg)

        @manage_changed
        def pop_flash(self, queue=''):
            storage = self.pop('_f_' + queue, [])
            return storage

        @manage_accessed
        def peek_flash(self, queue=''):
            storage = self.get('_f_' + queue, [])
            return storage

        # CSRF API methods
        @manage_changed
        def new_csrf_token(self):
            token = self._get_random()
            self['_csrft_'] = token
            return token

        @manage_accessed
        def get_csrf_token(self):
            token = self.get('_csrft_', None)
            if token is None:
                token = self.new_csrf_token()
            return token

        def _get_cookie(self):  # cookie value, not file value itself
            value = self.request.cookies.get(self._cookie_name, '')
            return value

        def _set_cookie(self, response):
            session = self.get('session', None)
            if session is None:
                return False

            cookieval = self.new and session['id'] or self._get_cookie()
            if not cookieval:
                return False

            response.set_cookie(
                self._cookie_name,
                value=cookieval,
                max_age=self._cookie_max_age,
                path=self._cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=self._cookie_httponly
                )
            return True

    return OktaSession