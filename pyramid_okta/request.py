__author__ = 'psuresh'

# from pyramid.decorator import reify

class OktaRequestExtra(object):

    def __init__(self, request):
        self.request = request
        self.session_token = None

    def set_access_token(self, token):
        self.session_token = token

    @property
    def access_token(self):
        return self.session_token

    def clear_access_token(self):
        self.session_token = None