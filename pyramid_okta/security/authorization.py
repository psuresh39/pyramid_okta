__author__ = 'psuresh'

# Use the default ACL policy and define permissions as ACL's`


class OktaAuthorizationPolicy(object):
    def permits(self, context, principals, permission):
        """ Return ``True`` if any of the ``principals`` is allowed the
        ``permission`` in the current ``context``, else return ``False``
        """

        if not permission:
            return True

        if permission in principals:
            return True
        else:
            return False

    def principals_allowed_by_permission(self, context, permission):
        """ Return a set of principal identifiers allowed by the
        ``permission`` in ``context``.  This behavior is optional; if you
        choose to not implement it you should define this method as
        something which raises a ``NotImplementedError``.  This method
        will only be called when the
        ``pyramid.security.principals_allowed_by_permission`` API is
        used."""
        raise NotImplementedError