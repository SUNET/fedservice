from fedservice.message import AuthorizationServerMetadata
from fedservice.message import FederationEntity
from fedservice.message import OauthClientMetadata
from fedservice.message import OAuthProtectedResourceMetadata
from fedservice.message import OIDCRPMetadata
from fedservice.message import OPMetadata

ENTITY_TYPE2METADATA_CLASS = {
    "openid_relying_party": OIDCRPMetadata,
    "openid_provider": OPMetadata,
    "oauth_authorization_server": AuthorizationServerMetadata,
    "oauth_client": OauthClientMetadata,
    "oauth_resource": OAuthProtectedResourceMetadata,
    "federation_entity": FederationEntity
}

DEFAULT_OIDC_FED_SERVICES = {
    'oidc_authorization': {
        'class': 'fedservice.appclient.oidc.authorization.Authorization'},
    'oidc_registration': {
        'class': 'fedservice.appclient.oidc.registration.Registration'},
}

DEFAULT_OAUTH2_FED_SERVICES = {
    'oauth_authorization': {
        'class': 'fedservice.appclient.oauth2.authorization.Authorization'},
    'oauth_registration': {
        'class': 'fedservice.appclient.oauth2.registration.Registration'},
}

COMBINED_DEFAULT_OIDC_SERVICES = DEFAULT_OIDC_FED_SERVICES
COMBINED_DEFAULT_OIDC_SERVICES.update({
    "discovery": {"class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"},
    "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
    "refresh_access_token": {
        "class": "idpyoidc.client.oidc.refresh_access_token.RefreshAccessToken"},
    "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"}
})

COMBINED_DEFAULT_OAUTH2_SERVICES = DEFAULT_OAUTH2_FED_SERVICES
COMBINED_DEFAULT_OAUTH2_SERVICES.update({
    "discovery": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "refresh_access_token": {
        "class": "idpyoidc.client.oauth2.refresh_access_token.RefreshAccessToken"}
})

SERVICES = {
    "entity_configuration": {
        "class": 'fedservice.entity.client.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "entity_statement": {
        "class": 'fedservice.entity.client.entity_statement.SubordinateStatement',
        "kwargs": {}
    },
    "trust_mark_status": {
        "class": 'fedservice.entity.client.trust_mark_status.TrustMarkStatus',
        "kwargs": {}
    },
    "trust_mark_list": {
        "class": 'fedservice.entity.client.trust_mark_list.TrustMarkList',
        "kwargs": {}
    },
    "trust_mark": {
        "class": 'fedservice.entity.client.trust_mark.TrustMark',
        "kwargs": {}
    },
    "resolve": {
        "class": 'fedservice.entity.client.resolve.Resolve',
        "kwargs": {}
    },
    "list": {
        "class": 'fedservice.entity.client.list.List',
        "kwargs": {}
    },
    "who": {
        "class": 'fedservice.entity.client.who.Who',
        "kwargs": {}
    },
}


def federation_services(*api):
    res = {}
    for a in api:
        if isinstance(a, dict):
            continue
        if a in SERVICES:
            res[a] = SERVICES[a]
        elif a in DEFAULT_OAUTH2_FED_SERVICES:
            res[a] = DEFAULT_OAUTH2_FED_SERVICES[a]
        elif a in DEFAULT_OIDC_FED_SERVICES:
            res[a] = DEFAULT_OIDC_FED_SERVICES[a]

    for a in api:
        if isinstance(a, dict):
            res.update(a)

    return res


FEDERATION_ENTITY_SERVICES = federation_services("entity_configuration", "entity_statement",
                                                 "resolve", "list")

DEFAULT_FEDERATION_ENTITY_SERVICES = FEDERATION_ENTITY_SERVICES

OIDC_FED_ENDPOINTS = {
    'oidc_authorization': {
        "path": "authn",
        'class': 'fedservice.appserver.oidc.authorization.Authorization',
        "kwargs": {}
    },
    'oidc_registration': {
        'class': 'fedservice.appserver.oidc.registration.Registration'},
}

OAUTH2_FED_ENDPOINTS = {
    'oauth_authorization': {
        "path": "authz",
        'class': 'fedservice.appserver.oauth2.authorization.Authorization'
    },
    'oauth_registration': {
        "path": "registration",
        'class': 'fedservice.appserver.oauth2.registration.Registration'
    }
}

FEDERATION_ENDPOINTS = {
    "entity_configuration": {
        "path": ".well-known/openid-federation",
        "class": 'fedservice.entity.server.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "fetch": {
        "path": "fetch",
        "class": 'fedservice.entity.server.fetch.Fetch',
        "kwargs": {}
    },
    "list": {
        "path": "list",
        "class": 'fedservice.entity.server.list.List',
        "kwargs": {}
    },
    "resolve": {
        "path": "resolve",
        "class": 'fedservice.entity.server.resolve.Resolve',
        "kwargs": {}
    },
    "trust_mark_status": {
        "path": "trust_mark_status",
        "class": 'fedservice.trust_mark_entity.server.trust_mark_status.TrustMarkStatus',
        "kwargs": {}
    },
    "trust_mark": {
        "path": "trust_mark",
        "class": 'fedservice.trust_mark_entity.server.trust_mark.TrustMark',
        "kwargs": {}
    },
    "trust_mark_list": {
        "path": "trust_mark_list",
        "class": 'fedservice.trust_mark_entity.server.trust_mark_list.TrustMarkList',
        "kwargs": {}
    },
    "who": {
        "path": "who",
        "class": "fedservice.entity.server.who.Who",
        "kwargs": {}
    }
}


def federation_endpoints(*apis) -> dict:
    interm = {a: FEDERATION_ENDPOINTS[a] for a in apis if isinstance(a, str)}
    for a in apis:
        if isinstance(a, dict):
            interm.update(a)
    return interm


INTERMEDIATE_ENDPOINTS = federation_endpoints("entity_configuration", "fetch", "list")
DEFAULT_FEDERATION_ENTITY_ENDPOINTS = INTERMEDIATE_ENDPOINTS

LEAF_ENDPOINTS = federation_endpoints("entity_configuration")

TRUST_MARK_ISSUER_ENDPOINTS = federation_endpoints("entity_configuration", "trust_mark_status",
                                                   "trust_mark", "trust_mark_list")

WELL_KNOWN_FEDERATION_ENDPOINT = "{}/.well-known/openid-federation"

FEDERATION_ENTITY_FUNCTIONS = {
    "trust_chain_collector": {
        "class": 'fedservice.entity.function.trust_chain_collector.TrustChainCollector',
        "kwargs": {
            'trust_anchors': {},
            "allowed_delta": 600
        }
    },
    'verifier': {
        'class': 'fedservice.entity.function.verifier.TrustChainVerifier',
        'kwargs': {}
    },
    'policy': {
        'class': 'fedservice.entity.function.policy.TrustChainPolicy',
        'kwargs': {}
    },
    'trust_mark_verifier': {
        'class': 'fedservice.entity.function.trust_mark_verifier.TrustMarkVerifier',
        'kwargs': {}
    },
    'metadata_verifier': {
        'class': 'fedservice.entity.function.metadata_verifier.MetadataVerifier',
        'kwargs': {}
    }
}


def federation_functions(*apis):
    return {a: FEDERATION_ENTITY_FUNCTIONS[a] for a in apis}


DEFAULT_FEDERATION_ENTITY_FUNCTIONS = federation_functions("trust_chain_collector", "verifier",
                                                           "policy", "trust_mark_verifier")

DEFAULT_SIGNING_ALGORITHM = "RS256"

DEFAULT_REGISTRATION_TYPE = "automatic"