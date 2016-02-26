from . import settings


def includeme(config):
    settings.API_TOKEN = config.registry.settings.get('okta.api_token', settings.API_TOKEN)
    settings.BASE_URL = config.registry.settings.get('okta.base_url', settings.BASE_URL)