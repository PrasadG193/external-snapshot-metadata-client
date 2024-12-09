# external-snapshot-metadata-client

Sample client to interact with [external-snapshot-metadata](https://github.com/kubernetes-csi/external-snapshot-metadata) service to query changed block metadata information between two CSI snapshots on Kubernetes.

### Usage

```
$ ./external-snapshot-metadata-client --help
Usage of /external-snapshot-metadata-client:
  -client-namespace string
        client namespace (default "default")
  -kubeconfig string
        Paths to a kubeconfig. Only required if out-of-cluster.
  -namespace string
        snapshot namespace (default "default")
  -service-account string
        client service account (default "default")
  -snapshot-1 string
        first volume snapshot name
  -snapshot-2 string
        second volume snapshot name
  -token-mount-path string
        Path to the token mounted with projected volume (default "/var/run/secrets/tokens/%s")
  -use-projected-token
        Use token mounted using project volume instead of creating new with TokenRequest
```
