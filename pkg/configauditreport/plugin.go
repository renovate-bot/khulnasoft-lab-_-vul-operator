package configauditreport

import (
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
)

// PluginInMemory defines the interface between vul-operator and vul configuration
type PluginInMemory interface {

	// Init is a callback to initialize this plugin, e.g. ensure the default
	// configuration.
	Init(ctx vuloperator.PluginContext) error

	NewConfigForConfigAudit(ctx vuloperator.PluginContext) (ConfigAuditConfig, error)
}

// ConfigAuditConfig defines the interface between vul-operator and vul configuration which related to configauditreport
type ConfigAuditConfig interface {

	// GetUseBuiltinRegoPolicies return vul config which associated to configauditreport plugin
	GetUseBuiltinRegoPolicies() bool
	// GetSupportedConfigAuditKinds list of supported kinds to be scanned by the config audit scanner
	GetSupportedConfigAuditKinds() []string

	// GetSeverity get security level
	GetSeverity() string
}
