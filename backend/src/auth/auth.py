import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'dev-xudjg1cu.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'http://localhost:5000'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''


def getHeader():
    head = request.headers.get("Authorization", None)
    return head


def raiseAuthError():
    raise AuthError({"code": "authorization_header_missing",
        "description": "Authorization header is expected"}, 401)


def splitHeader(header):
    sh = header.split(' ')
    return sh
    

def get_token_auth_header():
    header = getHeader()
    if not header:
       raiseAuthError() 

    sh = splitHeader(header)

    if sh[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)
    elif len(sh) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        })

    elif len(sh) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        })
    
    token = sh[1]
    return token

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_raiseAuthError():
    raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

def check_raiseAuthError2():
    raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 401)

def check_permissions(permission, payload):
    if 'permissions' not in payload:
        check_raiseAuthError()

    if permission not in payload['permissions']:
        check_raiseAuthError2()

    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def uVH_raiseAuthError():
    raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

def uVH_decode(token, uVHcheck):
    uVH_decode = jwt.decode(token, uVHcheck, algorithms=ALGORITHMS,
                 audience=API_AUDIENCE, issuer='https://' + AUTH0_DOMAIN + '/')
    return uVH_decode             


def invalid_header():
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)

def invalid_header2():
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)


def expired():
    raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

def invalid_claims():
    raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)


def jsUrl():
    js = json.loads(urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json').read())
    return js

def uVH(token):
    uVH =jwt.get_unverified_header(token)
    return uVH



def verify_decode_jwt(token):
    jsonUrl = jsUrl()
    uVHH = uVH(token)

    if 'kid' not in uVHH:
        uVH_raiseAuthError()

    uVHcheck = {}
    for key in jsonUrl['keys']:
        if key['kid'] == uVHH['kid']:
            uVHcheck = {'kty': key['kty'],'kid': key['kid'],'use': key['use'],'n': key['n'],'e': key['e']}
    if uVHcheck:
        try:
            return uVH_decode(token, uVHcheck)

        except jwt.ExpiredSignatureError:
            expired()

        except jwt.JWTClaimsError:
            invalid_claims()

        except Exception:
           invalid_header()

    invalid_header2()
'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except:
                abort(401)
            
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator