from django.contrib.auth.middleware import RemoteUserMiddleware
from django.contrib.auth.backends import RemoteUserBackend
from .ipsettings import setting
import jwt
import requests

class CustomHeaderMiddleware(RemoteUserMiddleware):
    header = 'HTTP_REMOTE_USER'


def isGood(request):
    token = request.POST.get('jwt')
    usr = jwt.get_unverified_header(token)['username']
    s = requests.Session()
    s.auth = ('broker', '6prZrrNwwQ5X54')
    s.headers.update({'Accept': 'application/json'})
    keys = None
    keys = s.get('https://'+setting['AUTH_SERVER']+'/pubkey/', verify=False, params={'username': usr}).json()

    client_decode = None
    try:
        client_decode = jwt.decode(token, keys['client']['public_key'], algorithms=['RS256'])
    except Exception as e:
        return None
    server_decode = None
    try:
        server_decode = jwt.decode(client_decode['client_acl_jwt'], keys['server'], algorithms=['RS256'])
    except Exception as e:
        return None

    for ele in server_decode['acl_payload']:
        if client_decode['topic'] == ele['topic']:
            if ele[client_decode['role']]:
                return usr, keys, client_decode['topic'], client_decode['role']
    return None


class JWTRemoteUser(RemoteUserBackend):
    def authenticate(self, request, remote_user):
        usr, keys, topic, role = None, None, None, None
        try:
            usr, keys, topic, role = isGood(request)
        except Exception as e:
            print(str(e))
        if usr is not None and usr == remote_user:
            print("Authenticated:"+usr)
            request.session['client_key'] = keys['client']['public_key']
            request.session['server_key'] = keys['server']
            request.session['role'] = role
            request.session['topic'] = topic
            return super().authenticate(request, remote_user)
        else:
            return None
