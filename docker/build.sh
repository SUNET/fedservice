#!/bin/bash
set -eo pipefail
git clone --no-checkout --depth 1 --sparse --filter=blob:none https://github.com/rohe/satosa-openid4vci
pushd satosa-openid4vci
git sparse-checkout init --cone
git sparse-checkout add example/flask_wallet/
git checkout main
cp -a example/flask_wallet ../../dc4eu_federation
popd
rm -rf satosa-openid4vci
pushd ../dc4eu_federation/flask_wallet
mv templates templates.orig
mv templates_simplified templates
mv conf_simplified.json conf.json
#mv views_simplified.py views.py
popd
docker build -t fedservice -f ./fedservice.Dockerfile .. --no-cache
