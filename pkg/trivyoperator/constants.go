package vuloperator

const (
	// NamespaceName the name of the namespace in which Vul-operator stores its
	// configuration and where it runs scan jobs.
	NamespaceName = "vul-operator"

	// ConfigMapName the name of the ConfigMap where Vul-operator stores its
	// configuration.
	ConfigMapName = "vul-operator"

	// SecretName the name of the secret where Vul-operator stores is sensitive
	// configuration.
	SecretName = "vul-operator"

	// PoliciesConfigMapName the name of the ConfigMap used to store OPA Rego
	// policies.
	PoliciesConfigMapName = "vul-operator-policies-config"
)

const (
	LabelResourceKind      = "vul-operator.resource.kind"
	LabelResourceName      = "vul-operator.resource.name"
	LabelResourceNameHash  = "vul-operator.resource.name-hash"
	LabelResourceNamespace = "vul-operator.resource.namespace"
	LabelContainerName     = "vul-operator.container.name"
	LabelResourceSpecHash  = "resource-spec-hash"
	LabelPluginConfigHash  = "plugin-config-hash"

	LabelVulnerabilityReportScanner = "vulnerabilityReport.scanner"
	LabelNodeInfoCollector          = "node-info.collector"

	LabelK8SAppManagedBy = "app.kubernetes.io/managed-by"
	AppVulOperator     = "vul-operator"
)

const (
	AnnotationContainerImages = "vul-operator.container-images"
)
