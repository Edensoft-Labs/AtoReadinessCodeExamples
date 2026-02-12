#!/bin/bash

# This is a wrapper script to run the Anchore Syft Software Bill of Materials (SBOM)
# generator against a specified Docker image. For ease of installation, Syft itself is run
# in a Docker conatiner.

# PARSE COMMAND-LINE ARGUMENTS.
CONTAINER_IMAGE_TO_SCAN="$1"

# GENERATE OUTPUT FILENAME FROM CONTAINER IMAGE NAME.
# Replace colons with dashes to create a valid filename.
OUTPUT_FILENAME="${CONTAINER_IMAGE_TO_SCAN//:/\-}.cdx.json"

# RUN THE SYFT SCAN.
# We remove the container after running it (--rm).
#
# Because bash doesn't let us put comments inline in a multi-line command very easily,
# the comments explaining each relevant part of the command are here:
#
#       --volume "/var/run/docker.sock:/var/run/docker.sock" \
#  Map the Docker daemon socket on the host into the container.
#  This is required so Syft running in its own container can inspect
#  other Docker images on this host.
#
#     --volume "$HOME/Library/Caches:/root/.cache/" \
#  Provide persistent storage for the scanner to store its vulnerability databases.
#  If this is not provided, the scanner re-downloads multi-gigabyte files on
#  each and every scan, which is not efficient.
docker run --rm \
    --volume "/var/run/docker.sock:/var/run/docker.sock" \
    --volume "$HOME/Library/Caches:/root/.cache/" \
    --name Syft anchore/syft:latest \
    "$CONTAINER_IMAGE_TO_SCAN" \
    -o cyclone-dx-json > "$OUTPUT_FILENAME"