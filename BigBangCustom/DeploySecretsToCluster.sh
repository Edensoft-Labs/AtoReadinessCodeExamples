#! /bin/bash

# This script is quick a one-time bootstrap to create the bigbang namespace and the secrets Flux/Big Bang need before
# the main deployment. This includes the SOPS decryption key, Git credentials, dev-bb-secret, and Iron Bank registry.
# Thus assumes `rke2_kubeconfig.yaml` has been copied to `~/.kube/config` for kubectl access.
# This should be run before applying dev/bigbang.yaml.

# CREATE THE NAMESPACE FOR BIG BANG.
kubectl create ns bigbang

# PROPAGATE THE PRIVATE KEY TO ALLOW FLUX TO DECRYPT SECRETS FROM THE GIT REPO.
# Ensure GPG_FP is set to your key fingerprint
export GPG_FP="YOUR_GPG_KEY_FINGERPRINT_HERE"
gpg --export-secret-key --armor "${GPG_FP}" | kubectl create secret generic sops-gpg -n bigbang --from-file=bigbangkey.asc=/dev/stdin
# Note that the `private-git` secret name is a `secretRef` in the `bigbang.yaml` file.
kubectl create secret generic private-git -n bigbang --from-literal=username=YOUR_GIT_USERNAME --from-literal=password=YOUR_GIT_PASSWORD_OR_TOKEN

# DEPLOY OTHER SECRETS.
# This secret must exist before deploying the actual Big Bang Helm chart.
kubectl apply -f dev/secrets/dev-bb-secret.yaml
# Docker registry credentials are needed to pull Iron Bank images.
kubectl create secret docker-registry private-registry -n bigbang --docker-server=registry1.dso.mil --docker-username=$REGISTRY1_USERNAME --docker-password=$REGISTRY1_PASSWORD
