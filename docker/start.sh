#!/bin/bash
set -eo pipefail

for file in conf.json views.py; do
    if [ -f /"${1}"/"${file}" ]; then
        echo "${file} found, leaving alone. Beware when upgrading."
        continue
    fi
    echo "No ${file} found, copying to /${1}/"
    if [ $file = conf.json ]; then
        jq --arg a "$FEDSERVICE_ENTITYID" ' .entity.entity_id = $a' /fedservice/dc4eu_federation/"${1}/${file}" > "${1}/${file}"
    else
        cp /fedservice/dc4eu_federation/"${1}/${file}" /"${1}"/
    fi
done
echo "Starting ${1}."
/fedservice/dc4eu_federation/entity.py "$@"
