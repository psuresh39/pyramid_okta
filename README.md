pyramid_okta
======================

The `pyramid_okta` project is aimed at providing an integration layer between the
okta user management system and the pyramid web framework, using the okta python package.

Installation
-----------------------

    pip install pyramid_okta

Usage
-----------------------

Inside your pyramid configuration file, just add the following parameters:

    include=
        pyramid_okta
    
    # okta configuration information
    okta.base_url = https://my_space.okta.com
    okta.api_token = 12345

License
------------------------

MIT license