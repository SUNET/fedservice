DEFAULT_OIDC_SERVICES = {
    "discovery": {"class": "idpyoidc.client.oidc.provider_info_discovery.ProviderInfoDiscovery"},
    "registration": {"class": "idpyoidc.client.oidc.registration.Registration"},
    "authorization": {"class": "idpyoidc.client.oidc.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oidc.access_token.AccessToken"},
    "refresh_access_token": {
        "class": "idpyoidc.client.oidc.refresh_access_token.RefreshAccessToken"
    },
    "userinfo": {"class": "idpyoidc.client.oidc.userinfo.UserInfo"},
}

DEFAULT_OAUTH2_SERVICES = {
    "discovery": {"class": "idpyoidc.client.oauth2.server_metadata.ServerMetadata"},
    "authorization": {"class": "idpyoidc.client.oauth2.authorization.Authorization"},
    "access_token": {"class": "idpyoidc.client.oauth2.access_token.AccessToken"},
    "refresh_access_token": {
        "class": "idpyoidc.client.oauth2.refresh_access_token.RefreshAccessToken"
    },
}
