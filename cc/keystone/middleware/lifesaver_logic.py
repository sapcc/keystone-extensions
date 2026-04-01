# Copyright 2018 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import hmac
import logging
import socket

LOG = logging.getLogger(__name__)

FTOKENCREDS_PREFIX = 'FTOKENCREDS-'


def extract_password_auth_credentials(request):
    """
    Extract user credentials from password authentication request body.
    
    Args:
        request: Request object
    Returns:
        tuple: (user, domain) or (None, None) if not found
    """
    
    try:
        body = request.json_body
    except Exception:
        # GET requests or requests without JSON body will fail here
        return None, None

    if '/v3/auth/tokens' == request.path and 'POST' == request.method:
        if 'auth' not in body:
            return None, None
        
        if 'identity' not in body['auth']:
            return None, None
        
        identity = body['auth']['identity']
        if 'password' not in identity:
            return None, None
        
        if 'user' not in identity['password']:
            return None, None
        
        user_data = identity['password']['user']
        
        # Extract user (prefer name, fallback to id with prefix)
        user = user_data.get('name', None)
        if not user and 'id' in user_data:
            user = 'id-' + user_data['id']
        
        # Extract domain (prefer name, fallback to id)
        domain = None
        if 'domain' in user_data:
            domain = user_data['domain'].get('name', None)
            if not domain and 'id' in user_data['domain']:
                domain = user_data['domain']['id']
        
        return user, domain
    return None, None


def extract_app_credential(request):
    """
    Extract application credential ID from request body.
    
    Args:
        request: Request object
    Returns:
        str: Application credential ID with 'ac-' prefix, or None if not found
    """
    try:
        body = request.json_body
    except Exception:
        # GET requests or requests without JSON body will fail here
        return None
    
    if '/v3/auth/tokens' == request.path and 'POST' == request.method:
        if 'auth' not in body:
            return None
        
        if 'identity' not in body['auth']:
            return None
        
        identity = body['auth']['identity']
        if 'application_credential' not in identity:
            return None
        
        app_cred_id = identity['application_credential'].get('id', None)
        if app_cred_id:
            return 'ac-' + app_cred_id
    
    return None


def extract_token_id(request):
    """
    Extract token ID from request body or headers.

    Args:
        request: Request object
    Returns:
        str: Token ID or None if not found
    """
    # Check POST body for token
    if request.path == '/v3/auth/tokens' and request.method == 'POST':
        try:
            body = request.json_body
            if 'auth' in body and 'identity' in body['auth']:
                if 'token' in body['auth']['identity']:
                    return body['auth']['identity']['token'].get('id', None)
        except Exception:
            # Failed to parse JSON body
            pass
    
    # Check GET headers for token
    if request.path == '/v3/auth/tokens' and request.method == 'GET':
        if request.headers and 'X-Subject-Token' in request.headers:
            return request.headers.get('X-Subject-Token', None)

    return None


def extract_s3_ec2_credentials(request):
    """
    Extract S3 or EC2 credentials from request body.
    
    Args:
        request: Request object
    Returns:
        tuple: (user with prefix 's3creds-' or 'ec2creds-', domain) or (None, None) if not found
    """
    if (('/v3/s3tokens' == request.path or
                   '/v3/ec2tokens' == request.path) and
                  'POST' == request.method):
        
        try:
            body = request.json_body
        except Exception:
            # Failed to parse JSON body
            return None, None

        # The order is taken from EC2_S3_Resource.py in keystone
        credentials = (
            body.get('credentials') or
            body.get('credential') or
            body.get('ec2Credentials')
        )
        
        if not credentials or 'access' not in credentials:
            return None, None
        
        # Determine prefix based on path
        prefix = 's3creds' if request.path == '/v3/s3tokens' else 'ec2creds'
        
        user = prefix + '-' + credentials['access']
        domain = 'unknown'  # ec2tokens and s3tokens API are domain unaware
        
        return user, domain
    return None, None


def extract_from_authentication_request(request):
    """
    Extract user identifier and domain from various authentication request types.
    
    Args:
        request: Request object
    Returns:
        tuple: (user, domain) or (None, None) if not found
    """
    context = request.environ
    user = None
    domain = None

    if 'KEYSTONE_AUTH_CONTEXT' not in context:
        return None, None
    # grab from request env
    if not user:
        user = context.get('HTTP_X_USER_NAME', None)
    if not domain:
        domain = context.get('HTTP_X_USER_DOMAIN_NAME', None)

    # try token info
    if not user or not domain:
        # grab from token
        token_info = context.get('keystone.token_info', None)
        if token_info:
            token = token_info.get('token', None)
            if token:
                user_info = token.get('user', None)
                if user_info:
                    user = user_info.get('name', None)
                    domain_info = user_info.get('domain', None)
                    if domain_info:
                        domain = domain_info.get('name', None)

    return user, domain


def hash_token_id(token_id: str, secret_key: str, hash_function: str = 'sha512') -> str:
    """Hash a token ID using HMAC.

    If secret_key is not set, the hostname is used as a fallback and a warning
    is logged. Token rate-limiting remains active but the hash is less secure.

    Args:
        token_id: The token ID to hash.
        secret_key: The secret key for HMAC.
        hash_function: The hash algorithm to use (default: sha512).

    Returns:
        The hexadecimal digest of the HMAC hash.
    """
    if not secret_key:
        LOG.warning(
            "security_compliance.invalid_password_hash_secret_key is not set. "
            "Token hashing will use the hostname as a fallback secret key. "
            "This reduces security — please configure a proper secret key."
        )
        secret_key = socket.getfqdn()

    return hmac.new(
        key=secret_key.encode('utf-8'),
        msg=token_id.encode('utf-8'),
        digestmod=hash_function
    ).hexdigest()


def calculate_cost(status_code, user_identifier, status_cost_config, token_cost_config):
    """
    Calculate the cost for a request based on status code and user type.
    
    Args:
        status_code: HTTP status code (int)
        user_identifier: User string (used to determine if token-based)
        status_cost_config: Dict of status codes to costs for regular users
        token_cost_config: Dict of status codes to costs for token users
    
    Returns:
        int: Cost to deduct from user's credit
    """
    # No cost for successful responses
    if status_code < 400:
        return 0
    
    # Determine which cost table to use based on user prefix
    if user_identifier.startswith(FTOKENCREDS_PREFIX):
        cost_table = token_cost_config
    else:
        cost_table = status_cost_config
    
    # Get cost for this status code, fallback to default
    status_str = str(status_code)
    if status_str in cost_table:
        return int(cost_table[status_str])
    
    return int(cost_table.get('default', 1))


def should_update_score_metadata(score, current_credit, current_refill_time, current_refill_amount):
    """
    Check if score metadata needs updating due to configuration changes.
    
    Args:
        score: Score object with credit, refill_time, refill_amount attributes
        current_credit: Current credit config value
        current_refill_time: Current refill time config value
        current_refill_amount: Current refill amount config value
    
    Returns:
        bool: True if metadata needs updating
    """
    return (score.credit != current_credit or 
            score.refill_time != current_refill_time or 
            score.refill_amount != current_refill_amount)
