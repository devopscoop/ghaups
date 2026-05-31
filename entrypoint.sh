#!/bin/bash
set -e

ARGS=""

if [ "${INPUT_NO_SCAN}" = "true" ]; then
    ARGS="$ARGS --no-scan"
fi

if [ "${INPUT_NO_UPDATE}" = "true" ]; then
    ARGS="$ARGS --no-update"
fi

if [ -n "${INPUT_LOG_LEVEL}" ]; then
    ARGS="$ARGS --log-level ${INPUT_LOG_LEVEL}"
fi

# shellcheck disable=SC2086
exec python /app/ghaups.py $ARGS $INPUT_FILES
