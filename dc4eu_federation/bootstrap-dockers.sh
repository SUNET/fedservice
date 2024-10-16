#!/usr/bin/env bash
set -eo pipefail
DOMAIN="${DOMAIN:-$(hostname -f)}"
TRUST_ANCHOR="https://${DOMAIN}:7001"
TRUST_MARK_ISSUER="https://${DOMAIN}:6001"
WALLET_PROVIDER="https://${DOMAIN}:5001"

# Get Trust Anchor
#
docker_args="run --rm -i -v .:/workdir --entrypoint python3 docker.sunet.se/fedservice:latest fedservice/dc4eu_federation"
docker $docker_args/get_info.py -k -t $TRUST_ANCHOR > trust_anchor.json

# Add Anchor to Trust Mark Issuer
docker ${docker_args}/add_info.py -s /workdir/trust_anchor.json -t /workdir/trust_mark_issuer/trust_anchors
rm -r trust_mark_issuer/authority_hints
echo -e "${TRUST_ANCHOR}" >> trust_mark_issuer/authority_hints

#./entity.py trust_mark_issuer &
#sleep 2
#
docker ${docker_args}/get_info.py -k -s "${TRUST_MARK_ISSUER}" > trust_mark_issuer.json
docker ${docker_args}/add_info.py -s /workdir/trust_mark_issuer.json -t workdir/trust_anchor/subordinates 

#FIXME: Special stuff here to get the paths right
docker run --rm -i -v .:/workdir -v ./trust_mark_issuer:/trust_mark_issuer --entrypoint python3 docker.sunet.se/fedservice:latest fedservice/dc4eu_federation/issuer.py /trust_mark_issuer > trust_mark_issuers.json
docker ${docker_args}/add_info.py -s workdir/trust_mark_issuers.json -t workdir/trust_anchor/trust_mark_issuers
#
## Wallet Provider
docker ${docker_args}/add_info.py -s workdir/trust_anchor.json -t workdir/wallet_provider/trust_anchors
rm -r wallet_provider/authority_hints
echo -e "${TRUST_ANCHOR}" >> wallet_provider/authority_hints
#
#./entity.py wallet_provider &
#sleep 2
#
docker "${docker_args}"/get_info.py -k -s "${WALLET_PROVIDER}" > wallet_provider.json
docker ${docker_args}/add_info.py -s /workdir/wallet_provider.json -t workdir/trust_anchor/subordinates
if [ ! -d lask_wallet/trust_anchors ]; then
    mkdir flask_wallet/trust_anchors
fi
cp -a wallet_provider/trust_anchors/* flask_wallet/trust_anchors/
echo "Place this into oidc_frontend.yaml below:" 
echo "config:             "
echo "  op:               " 
echo "    server_info:    "
echo "      trust_anchors:"
./convert_json_to_yaml.py trust_anchor.json
#
## Query Server
#./add_info.py -s trust_anchor.json -t query_server/trust_anchors
#rm -r query_server/authority_hints
#echo -e "https://127.0.0.1:7003" >> query_server/authority_hints
#
#./entity.py query_server &
#sleep 2
#
#./get_info.py -k -s https://127.0.0.1:6005 > tmp.json
#./add_info.py -s tmp.json -t trust_anchor/subordinates

## PID Issuer
#./add_info.py -s trust_anchor.json -t pid_issuer/trust_anchors
#rm -r pid_issuer/authority_hints
#echo -e "https://127.0.0.1:7003" >> pid_issuer/authority_hints
#
#./entity.py pid_issuer &
#sleep 2
#
#./get_info.py -k -s https://127.0.0.1:6001 > tmp.json
#./add_info.py -s tmp.json -t trust_anchor/subordinates
