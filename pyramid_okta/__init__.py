from pyramid_okta import settings
from pyramid_okta.security.authentication import OktaAuthenticationPolicy
from pyramid_okta.security.authorization import OktaAuthorizationPolicy
from pyramid_okta.request import OktaRequestExtra
from pyramid_okta.session import OktaSessionFactory


def includeme(config):
    settings.API_TOKEN = config.registry.settings.get('okta.api_token', settings.API_TOKEN)
    settings.BASE_URL = config.registry.settings.get('okta.base_url', settings.BASE_URL)

    # set up authn/z policies
    config.set_authentication_policy(OktaAuthenticationPolicy())
    config.set_authorization_policy(OktaAuthorizationPolicy())

    # set up request methods
    config.add_request_method(OktaRequestExtra, 'okta_extras', property=True)