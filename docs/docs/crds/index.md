# Overview

This project houses CustomResourceDefinitions (CRDs) related to security and compliance checks along with the code
generated by Kubernetes [code generators][k8s-code-generator] to write such custom resources in a programmable way.

| NAME                          | SHORTNAMES                                              | APIGROUP               | NAMESPACED | KIND                                                             |
|-------------------------------|---------------------------------------------------------|------------------------|------------|------------------------------------------------------------------|
| [vulnerabilityreports]        | vulns,vuln                                              | khulnasoft-lab.github.io | true       | [VulnerabilityReport](./vulnerability-report.md)                 |
| [configauditreports]          | configaudit,configaudits                                | khulnasoft-lab.github.io | true       | [ConfigAuditReport](./configaudit-report.md)                     |
| [exposedsecretsreports]       | exposedsecret,exposedsecrets                            | khulnasoft-lab.github.io | true       | [ExposedSecretReport](./exposedsecret-report.md)                 |
| [rbacassessmentreports]       | rbacassessmentreports,rbacassessmentreport              | khulnasoft-lab.github.io | true       | [RbacAssessmentReport](./rbacassessment-report.md)               |
| [clusterrbacassessmentreports] |clusterrbacassessmentreports,clusterrbacassessmentreport | khulnasoft-lab.github.io | true       | [ClusterRbacAssessmentReport](./clusterrbacassessment-report.md) |
| [clusterinfraassessmentreports]|clusterinfraassessmentreports,clusterinfraassessmentreport | khulnasoft-lab.github.io | true       | [ClusterInfraAssessmentReport](./clusterrbacassessment-report.md) |
| [infraassessmentreports]       |infraassessmentreports,infraassessmentreport | khulnasoft-lab.github.io | true       | [InfraAssessmentReport](./clusterrbacassessment-report.md) |
| [sbomreports]       |sbomreports,sbomreport | khulnasoft-lab.github.io | true       | [SbomReport](./sbom-report.md) |

[k8s-code-generator]: https://github.com/kubernetes/code-generator

[vulnerabilityreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_vulnerabilityreports.yaml
[configauditreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_configauditreports.yaml
[exposedsecretsreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_exposedsecretreports.yaml
[rbacassessmentreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_rbacassessmentreports.yaml
[clusterrbacassessmentreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_clusterrbacassessmentreports.yaml
[clusterinfraassessmentreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_clusterinfraassessmentreports.yaml
[infraassessmentreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_infraassessmentreports.yaml
[sbomreports]: https://raw.githubusercontent.com/khulnasoft-lab/vul-operator/{{ git.tag }}/deploy/helm/crds/khulnasoft-lab.github.io_sbomreports.yaml
