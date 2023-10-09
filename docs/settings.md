# Settings

The Starboard CLI and Starboard Operator read configuration settings from ConfigMaps, as well as Secrets that holds
confidential settings (such as a GitHub token). Starboard plugins read configuration and secret data from ConfigMaps
and Secrets named after the plugin. For example, Vul configuration is stored in the ConfigMap and Secret named
`starboard-vul-config`.

The `starboard install` command ensures the `starboard` ConfigMap and the `starboard` Secret in the `starboard`
namespace with default settings. Similarly, the operator ensures the `starboard` ConfigMap and the `starboard` Secret in
the `OPERATOR_NAMESPACE`.

You can change the default settings with `kubectl patch` or `kubectl edit` commands. For example, by default Vul
displays vulnerabilities with all severity levels (`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). However, you can
display only `HIGH` and `CRITICAL` vulnerabilities by patching the `vul.severity` value in the `starboard-vul-config`
ConfigMap:

```
STARBOARD_NAMESPACE=<your starboard namespace>
```
```
kubectl patch cm starboard-vul-config -n $STARBOARD_NAMESPACE \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "vul.severity": "HIGH,CRITICAL"
  }
}
EOF
)"
```

To set the GitHub token used by Vul add the `vul.githubToken` value to the `starboard-vul-config` Secret:

```
STARBOARD_NAMESPACE=<your starboard namespace>
GITHUB_TOKEN=<your token>
```
```
kubectl patch secret starboard-vul-config -n $STARBOARD_NAMESPACE \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "vul.githubToken": "$(echo -n $GITHUB_TOKEN | base64)"
  }
}
EOF
)"
```

The following table lists available settings with their default values. Check plugins' documentation to see
configuration settings for common use cases. For example, switch Vul from [Standalone] to [ClientServer] mode.

| CONFIGMAP KEY                                  | DEFAULT                               | DESCRIPTION                                                                                                                                                                                                                         |
|------------------------------------------------|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `vulnerabilityReports.scanner`                 | `Vul`                               | The name of the plugin that generates vulnerability reports. Either `Vul` or `Khulnasoft`.                                                                                                                                              |
| `vulnerabilityReports.scanJobsInSameNamespace` | `"false"`                             | Whether to run vulnerability scan jobs in same namespace of workload. Set `"true"` to enable.                                                                                                                                       |
| `configAuditReports.scanner`                   | `Polaris`                             | The name of the plugin that generates config audit reports. Either `Polaris` or `Conftest`.                                                                                                                                         |
| `scanJob.tolerations`                          | N/A                                   | JSON representation of the [tolerations] to be applied to the scanner pods so that they can run on nodes with matching taints. Example: `'[{"key":"key1", "operator":"Equal", "value":"value1", "effect":"NoSchedule"}]'`           |
| `scanJob.annotations`                          | N/A                                   | One-line comma-separated representation of the annotations which the user wants the scanner pods to be annotated with. Example: `foo=bar,env=stage` will annotate the scanner pods with the annotations `foo: bar` and `env: stage` |
| `scanJob.templateLabel`                        | N/A                                   | One-line comma-separated representation of the template labels which the user wants the scanner pods to be labeled with. Example: `foo=bar,env=stage` will labeled the scanner pods with the labels `foo: bar` and `env: stage`     |
| `kube-bench.imageRef`                          | `docker.io/khulnasoft/kube-bench:v0.6.9` | kube-bench image reference                                                                                                                                                                                                          |
| `kube-hunter.imageRef`                         | `docker.io/khulnasoft/kube-hunter:0.6.5` | kube-hunter image reference                                                                                                                                                                                                         |
| `kube-hunter.quick`                            | `"false"`                             | Whether to use kube-hunter's "quick" scanning mode (subnet 24). Set to `"true"` to enable.                                                                                                                                          |
| `compliance.failEntriesLimit`                  | `"10"`                                | Limit the number of fail entries per control check in the cluster compliance detail report.                                                                                                                                         |

!!! tip
    You can find it handy to delete a configuration key, which was not created by default by the `starboard install`
    command. For example, the following `kubectl patch` command deletes the `vul.httpProxy` key:
    ```
    STARBOARD_NAMESPACE=<your starboard namespace>
    ```
    ```
    kubectl patch cm starboard-vul-config -n $STARBOARD_NAMESPACE \
      --type json \
      -p '[{"op": "remove", "path": "/data/vul.httpProxy"}]'
    ```

[Standalone]: ./vulnerability-scanning/vul.md#standalone
[ClientServer]: ./vulnerability-scanning/vul.md#clientserver
[tolerations]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration
