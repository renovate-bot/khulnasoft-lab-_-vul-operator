package plugins

import (
	"github.com/khulnasoft-lab/vul-operator/pkg/configauditreport"
	"github.com/khulnasoft-lab/vul-operator/pkg/ext"
	"github.com/khulnasoft-lab/vul-operator/pkg/kube"
	"github.com/khulnasoft-lab/vul-operator/pkg/plugins/vul"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	"github.com/khulnasoft-lab/vul-operator/pkg/vulnerabilityreport"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Resolver struct {
	buildInfo          vuloperator.BuildInfo
	config             vuloperator.ConfigData
	namespace          string
	serviceAccountName string
	client             client.Client
	objectResolver     *kube.ObjectResolver
}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) WithBuildInfo(buildInfo vuloperator.BuildInfo) *Resolver {
	r.buildInfo = buildInfo
	return r
}

func (r *Resolver) WithConfig(config vuloperator.ConfigData) *Resolver {
	r.config = config
	return r
}

func (r *Resolver) WithNamespace(namespace string) *Resolver {
	r.namespace = namespace
	return r
}

func (r *Resolver) WithServiceAccountName(name string) *Resolver {
	r.serviceAccountName = name
	return r
}

func (r *Resolver) WithClient(c client.Client) *Resolver {
	r.client = c
	return r
}
func (r *Resolver) WithObjectResolver(objectResolver *kube.ObjectResolver) *Resolver {
	r.objectResolver = objectResolver
	return r
}

// GetVulnerabilityPlugin is a factory method that instantiates the vulnerabilityreport.Plugin.
//
// Vul-Operator currently supports Vul scanner in Standalone and ClientServer
// mode.
//
// You could add your own scanner by implementing the vulnerabilityreport.Plugin interface.
func (r *Resolver) GetVulnerabilityPlugin() (vulnerabilityreport.Plugin, vuloperator.PluginContext, error) {
	scanner, err := r.config.GetVulnerabilityReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := vuloperator.NewPluginContext().
		WithName(string(scanner)).
		WithClient(r.client).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithVulOperatorConfig(r.config).
		Get()

	return vul.NewPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.objectResolver), pluginContext, nil
}

// GetConfigAuditPlugin is a factory method that instantiates the configauditreport.Plugin.
func (r *Resolver) GetConfigAuditPlugin() (configauditreport.PluginInMemory, vuloperator.PluginContext, error) {
	scanner, err := r.config.GetConfigAuditReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := vuloperator.NewPluginContext().
		WithName(string(scanner)).
		WithClient(r.client).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithVulOperatorConfig(r.config).
		Get()

	return vul.NewVulConfigAuditPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.objectResolver), pluginContext, nil
}
