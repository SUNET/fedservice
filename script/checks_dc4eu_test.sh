# Trust Anchor: https://127.0.0.1:7003
# Trust Mark Issuer: https://127.0.0.1:6000
# Wallet Provider: https://127.0.0.1:5001
# Credential Issuer: https://127.0.0.1:8080

# ============= Get the entity configuration =============
#usage: get_entity_configuration.py [-h] [-k] [-f] [-t TRUST_ANCHORS_FILE] entity_id
#
#positional arguments:
#  entity_id
#
#options:
#  -h, --help            show this help message and exit
#  -k, --insecure
#  -f, --format
#  -t TRUST_ANCHORS_FILE, --trust_anchors_file TRUST_ANCHORS_FILE

./get_entity_configuration.py -k -t ../setup_federation/trust_anchor.json https://127.0.0.1:5001

# ============= Get subordinate statement from superior =============
#usage: get_subordinate_statement.py [-h] [-k] [-f] [-t TRUST_ANCHORS_FILE] [-s SUPERIOR] entity_id
#
#positional arguments:
#  entity_id
#
#options:
#  -h, --help            show this help message and exit
#  -k, --insecure
#  -f, --format
#  -t TRUST_ANCHORS_FILE, --trust_anchors_file TRUST_ANCHORS_FILE
#  -s SUPERIOR, --superior SUPERIOR

./get_subordinate_statement.py -k -t ../setup_federation/trust_anchor.json -s https://127.0.0.1:7003 https://127.0.0.1:5001

# ============= Get Trust Chain =============
#usage: get_trust_chains.py [-h] [-k] [-f] [-t TRUST_ANCHORS] [-l] url
#
#positional arguments:
#  url
#
#options:
#  -h, --help        show this help message and exit
#  -k
#  -t TRUST_ANCHORS
#  -l

./get_trust_chains.py -k -t ../setup_federation/trust_anchor.json https://127.0.0.1:5001
./get_trust_chains.py -k -t ../setup_federation/trust_anchor.json https://127.0.0.1:6000
./get_trust_chains.py -k -t ../setup_federation/trust_anchor.json https://127.0.0.1:8080

# ============= Get new trust mark =============
#usage: get_trust_mark.py [-h] [-k] [-f] [-t TRUST_ANCHORS] [-i TRUST_MARK_TYPE] [-s SUBJECT] entity_id
#
#positional arguments:
#  entity_id
#
#options:
#  -h, --help            show this help message and exit
#  -k, --insecure
#  -f, --format
#  -t TRUST_ANCHORS, --trust_anchors TRUST_ANCHORS
#  -i TRUST_MARK_TYPE, --trust_mark_type TRUST_MARK_TYPE
#  -s SUBJECT, --subject SUBJECT

./get_trust_mark.py -k -t ../setup_federation/trust_anchor.json -i http://dc4eu.example.com/PersonIdentificationData/se -s https://127.0.0.1:8080 https://127.0.0.1:6000

# ============= Check Trust Mark status =============
#usage: get_trust_mark_status.py [-h] [-k] [-f] [-i TRUST_MARK_TYPE] [-s SUBJECT] [-t TRUST_ANCHORS] entity_id
#
#positional arguments:
#  entity_id
#
#options:
#  -h, --help            show this help message and exit
#  -k, --insecure
#  -i TRUST_MARK_TYPE, --trust_mark_type TRUST_MARK_TYPE
#  -s SUBJECT, --subject SUBJECT
#  -t TRUST_ANCHORS, --trust_anchors TRUST_ANCHORS

./get_trust_mark_status.py -k -t ../setup_federation/trust_anchor.json -i http://dc4eu.example.com/PersonIdentificationData/se -s https://127.0.0.1:8080 https://127.0.0.1:6000

# ============= List subordinates ================
#usage: list_subordinates.py [-h] [-k] [-f] [-t TRUST_ANCHORS_FILE] [-s SUPERIOR] entity_id
#
#positional arguments:
#  entity_id
#
#options:
#  -h, --help            show this help message and exit
#  -k, --insecure
#  -t TRUST_ANCHORS_FILE, --trust_anchors_file TRUST_ANCHORS_FILE
#  -s SUPERIOR, --superior SUPERIOR

./list_subordinates.py -k -t ../setup_federation/trust_anchor.json https://127.0.0.1:7003

# ============= Resolve entity =============
#usage: resolve_entity.py [-h] [-k] [-f] [-t TRUST_ANCHOR] [-T TRUST_ANCHOR_FILE] [-r RESOLVER] entity_id
#
#positional arguments:
#  entity_id
#
#options:
#  -h, --help            show this help message and exit
#  -k, --insecure
#  -f, --format
#  -t TRUST_ANCHOR, --trust_anchor TRUST_ANCHOR
#  -T TRUST_ANCHOR_FILE, --trust_anchor_file TRUST_ANCHOR_FILE
#  -r RESOLVER, --resolver RESOLVER

./resolve_entity.py -k -T ../setup_federation/trust_anchor.json -r https://127.0.0.1:7003 -t https://127.0.0.1:7003 https://127.0.0.1:8080