from ..overrides import override
from ..importer import modules

Signon = modules['Signon']._introspection_module

__all__ = []

class AuthSession(Signon.AuthSession):

    # Convert list of strings into a single string
    def process(self, session_data, mechanism, callback, userdata):
        cleaned_data = {}
        for (key, value) in session_data.iteritems():
            if isinstance(value, list):
                # use a tab as separator; we can improve this later
                sep = '\t'
                joined_values = 'pySignon%s%s' % (sep, sep.join(value))
                cleaned_data[key] = joined_values
            else:
                cleaned_data[key] = value
        Signon.AuthSession.process(self, cleaned_data, mechanism, callback, userdata)

AuthSession = override(AuthSession)
__all__.append('AuthSession')


