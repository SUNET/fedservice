from idpyoidc.key_import import import_jwks


def federation_entity(unit):
    if hasattr(unit, "upstream_get"):
        if unit.upstream_get:
            next_unit = unit.upstream_get("unit")
            if next_unit:
                # This is slightly awkward. Can't use isinstance because of circular imports
                if unit.__class__.__name__ == 'FederationEntity':
                    return next_unit
                unit = federation_entity(next_unit)
    else:
        # Unit might be a FederationCombo instance or something equivalent
        if "federation_entity" in unit:
            return unit["federation_entity"]
    return unit


def get_federation_entity(unit):
    # Look both upstream and downstream if necessary
    if unit.__class__.__name__ == 'FederationEntity':
        return unit
    _ug = getattr(unit, 'upstream_get', None)
    if _ug:
        return get_federation_entity(_ug('unit'))

    _get = getattr(unit, "get", None)
    if _get:
        return _get('federation_entity', None)

    _get_guise = getattr(unit, "get_guise", None)
    if _get_guise:
        return _get_guise("federation_entity")
    else:
        return None


def get_verified_jwks(unit, _signed_jwks_uri):
    # Fetch a signed JWT that contains a JWKS.
    # Verify the signature on the JWS with a federation key
    # To be implemented
    return None


def get_keys(metadata, keyjar, entity_id, unit):
    _signed_jwks_uri = metadata.get('signed_jwks_uri')
    if _signed_jwks_uri:
        if _signed_jwks_uri:
            _jwks = get_verified_jwks(unit, _signed_jwks_uri)
            if _jwks:
                keyjar.add(entity_id, _jwks)
    else:
        _jwks_uri = metadata.get('jwks_uri')
        if _jwks_uri:
            keyjar.add_url(entity_id, _jwks_uri)
        else:
            _jwks = metadata.get('jwks')
            if _jwks:
                keyjar.import_jwks(_jwks, entity_id)
            else:
                raise ValueError("Missing key specification")
