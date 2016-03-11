from . import settings
from pyramid_okta.security.authentication import OktaAuthenticationPolicy
from pyramid_okta.security.authorization import OktaAuthorizationPolicy


def includeme(config):
    settings.API_TOKEN = config.registry.settings.get('okta.api_token', settings.API_TOKEN)
    settings.BASE_URL = config.registry.settings.get('okta.base_url', settings.BASE_URL)
    config.set_authentication_policy(OktaAuthenticationPolicy())
    config.set_authorization_policy(OktaAuthorizationPolicy())