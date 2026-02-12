Basic steps for the setup if you need to deploy anything here:
1. You'll need a Platform One account to be able to provide credentials for Iron Bank registry access.  Account can be created at https://login.dso.mil.
2. Depending on how you're deploying, you may need to temporarily add in those credentials to the respective secret files.  But don't check in such unencrypted files into version control.
3. Make sure you have your `kubeconfig` file for your local system set up.  On RKE2 clusters, this file comes from `/etc/rancher/rke2/rke2.yaml` on the server nodes.  Copy it to `~/.kube/config` on your local machine (where `config` is the resulting filename).
4. `DeploySecretsToCluster.sh` hopefully doesn't need to be re-run unless changing some of those values.  But if changing some values, you may need to re-run it before Big Bang deployment.  There are some environment variables you may need to set for the registry credentials before running.
5. `kubectl apply -f dev/bigbang.yaml` is how to redeploy what's locally here (though generally best to check things into the version controlled repo first).
6. `kubectl get helmreleases -n bigbang` is the main useful command for checking on the status of Helm Releases for Big Bang.  If something is failing, `kubectl describe helmrelease {release-name} -n bigbang` is the next most useful thing to typically check.  After that, other regular Kubernetes commands or ChatGPT may be useful.

The `dev/configmap.yaml` is the main "Big Bang values" file to be modified to customize what is deployed in the Big Bang cluster.
Generally speaking, you update that file, check it into your remote Git repo (update the URL in `dev/configmap.yaml` to point to your repository),
and then the cluster should automatically pick up on changes within a few minutes and start making adjustments.
However, you may want to run `kubectl apply -f dev/bigbang.yaml` directly to ensure that your specific local changes are applied.
