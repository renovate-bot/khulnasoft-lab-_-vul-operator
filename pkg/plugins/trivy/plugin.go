package vul

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/khulnasoft-lab/vul-db/pkg/types"
	"github.com/khulnasoft-lab/vul-operator/pkg/utils"
	fg "github.com/khulnasoft-lab/vul/pkg/flag"
	tr "github.com/khulnasoft-lab/vul/pkg/report"
	ty "github.com/khulnasoft-lab/vul/pkg/types"
	containerimage "github.com/google/go-containerregistry/pkg/name"

	"github.com/khulnasoft-lab/vul-operator/pkg/configauditreport"

	"github.com/khulnasoft-lab/vul-operator/pkg/apis/khulnasoft-lab/v1alpha1"
	"github.com/khulnasoft-lab/vul-operator/pkg/docker"
	"github.com/khulnasoft-lab/vul-operator/pkg/ext"
	"github.com/khulnasoft-lab/vul-operator/pkg/kube"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	"github.com/khulnasoft-lab/vul-operator/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Vul"
)

const (
	GCPCR_Inage_Regex         = `^(gcr\.io.*|^([a-zA-Z0-9-]+)-*-*.docker.pkg.dev.*)`
	AWSECR_Image_Regex        = "^\\d+\\.dkr\\.ecr\\.(\\w+-\\w+-\\d+)\\.amazonaws\\.com\\/"
	SupportedConfigAuditKinds = "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota"
	// SkipDirsAnnotation annotation  example: vul-operator.khulnasoft-lab.github.io/skip-dirs: "/tmp,/home"
	SkipDirsAnnotation = "vul-operator.khulnasoft-lab.github.io/skip-dirs"
	// SkipFilesAnnotation example: vul-operator.khulnasoft-lab.github.io/skip-files: "/src/Gemfile.lock,/examplebinary"
	SkipFilesAnnotation = "vul-operator.khulnasoft-lab.github.io/skip-files"
)

const (
	keyVulImageRepository = "vul.repository"
	keyVulImageTag        = "vul.tag"
	//nolint:gosec
	keyVulImagePullSecret                     = "vul.imagePullSecret"
	keyVulImagePullPolicy                     = "vul.imagePullPolicy"
	keyVulMode                                = "vul.mode"
	keyVulAdditionalVulnerabilityReportFields = "vul.additionalVulnerabilityReportFields"
	keyVulCommand                             = "vul.command"
	KeyVulSeverity                            = "vul.severity"
	keyVulSlow                                = "vul.slow"
	keyVulVulnType                            = "vul.vulnType"
	keyVulIgnoreUnfixed                       = "vul.ignoreUnfixed"
	keyVulOfflineScan                         = "vul.offlineScan"
	keyVulTimeout                             = "vul.timeout"
	keyVulIgnoreFile                          = "vul.ignoreFile"
	keyVulIgnorePolicy                        = "vul.ignorePolicy"
	keyVulInsecureRegistryPrefix              = "vul.insecureRegistry."
	keyVulNonSslRegistryPrefix                = "vul.nonSslRegistry."
	keyVulMirrorPrefix                        = "vul.registry.mirror."
	keyVulHTTPProxy                           = "vul.httpProxy"
	keyVulHTTPSProxy                          = "vul.httpsProxy"
	keyVulNoProxy                             = "vul.noProxy"
	keyVulSslCertDir                          = "vul.sslCertDir"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyVulGitHubToken          = "vul.githubToken"
	keyVulSkipFiles            = "vul.skipFiles"
	keyVulSkipDirs             = "vul.skipDirs"
	keyVulDBRepository         = "vul.dbRepository"
	keyVulJavaDBRepository     = "vul.javaDbRepository"
	keyVulDBRepositoryInsecure = "vul.dbRepositoryInsecure"

	keyVulUseBuiltinRegoPolicies    = "vul.useBuiltinRegoPolicies"
	keyVulSupportedConfigAuditKinds = "vul.supportedConfigAuditKinds"

	keyVulServerURL              = "vul.serverURL"
	keyVulClientServerSkipUpdate = "vul.clientServerSkipUpdate"
	keyVulSkipJavaDBUpdate       = "vul.skipJavaDBUpdate"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyVulServerTokenHeader = "vul.serverTokenHeader"
	keyVulServerInsecure    = "vul.serverInsecure"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyVulServerToken         = "vul.serverToken"
	keyVulServerCustomHeaders = "vul.serverCustomHeaders"

	keyResourcesRequestsCPU             = "vul.resources.requests.cpu"
	keyResourcesRequestsMemory          = "vul.resources.requests.memory"
	keyResourcesLimitsCPU               = "vul.resources.limits.cpu"
	keyResourcesLimitsMemory            = "vul.resources.limits.memory"
	keyResourcesRequestEphemeralStorage = "vul.resources.requests.ephemeral-storage"
	keyResourcesLimitEphemeralStorage   = "vul.resources.limits.ephemeral-storage"
)

const (
	DefaultImageRepository  = "ghcr.io/khulnasoft-lab/vul"
	DefaultDBRepository     = "ghcr.io/khulnasoft-lab/vul-db"
	DefaultJavaDBRepository = "ghcr.io/khulnasoft-lab/vul-java-db"
	DefaultSeverity         = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
)

// Mode in which Vul client operates.
type Mode string

const (
	Standalone   Mode = "Standalone"
	ClientServer Mode = "ClientServer"
)

// Command to scan image or filesystem.
type Command string

const (
	Filesystem Command = "filesystem"
	Image      Command = "image"
	Rootfs     Command = "rootfs"
)

type AdditionalFields struct {
	Description bool
	Links       bool
	CVSS        bool
	Target      bool
	Class       bool
	PackageType bool
	PkgPath     bool
}

// Config defines configuration params for this plugin.
type Config struct {
	vuloperator.PluginConfig
}

func (c Config) GetAdditionalVulnerabilityReportFields() AdditionalFields {
	addFields := AdditionalFields{}

	fields, ok := c.Data[keyVulAdditionalVulnerabilityReportFields]
	if !ok {
		return addFields
	}
	for _, field := range strings.Split(fields, ",") {
		switch strings.TrimSpace(field) {
		case "Description":
			addFields.Description = true
		case "Links":
			addFields.Links = true
		case "CVSS":
			addFields.CVSS = true
		case "Target":
			addFields.Target = true
		case "Class":
			addFields.Class = true
		case "PackageType":
			addFields.PackageType = true
		case "PackagePath":
			addFields.PkgPath = true
		}
	}
	return addFields
}

// GetImageRef returns upstream Vul container image reference.
func (c Config) GetImageRef() (string, error) {
	repository, err := c.GetRequiredData(keyVulImageRepository)
	if err != nil {
		return "", err
	}
	tag, err := c.GetImageTag()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s", repository, tag), nil
}

// GetImageTag returns upstream Vul container image tag.
func (c Config) GetImageTag() (string, error) {
	tag, err := c.GetRequiredData(keyVulImageTag)
	if err != nil {
		return "", err
	}
	return tag, nil
}

func (c Config) GetImagePullSecret() []corev1.LocalObjectReference {
	ips, ok := c.Data[keyVulImagePullSecret]
	if !ok {
		return []corev1.LocalObjectReference{}
	}
	return []corev1.LocalObjectReference{{Name: ips}}
}

func (c Config) GetImagePullPolicy() string {
	ipp, ok := c.Data[keyVulImagePullPolicy]
	if !ok {
		return "IfNotPresent"
	}
	return ipp
}

func (c Config) GetMode() (Mode, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyVulMode]; !ok {
		return "", fmt.Errorf("property %s not set", keyVulMode)
	}

	switch Mode(value) {
	case Standalone:
		return Standalone, nil
	case ClientServer:
		return ClientServer, nil
	}

	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s)",
		value, keyVulMode, Standalone, ClientServer)
}

func (c Config) GetCommand() (Command, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyVulCommand]; !ok {
		// for backward compatibility, fallback to ImageScan
		return Image, nil
	}
	switch Command(value) {
	case Image:
		return Image, nil
	case Filesystem:
		return Filesystem, nil
	case Rootfs:
		return Rootfs, nil
	}
	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s, %s)",
		value, keyVulCommand, Image, Filesystem, Rootfs)
}

func (c Config) GetServerURL() (string, error) {
	return c.GetRequiredData(keyVulServerURL)
}

func (c Config) GetClientServerSkipUpdate() bool {
	val, ok := c.Data[keyVulClientServerSkipUpdate]
	if !ok {
		return false
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return boolVal
}

func (c Config) GetSkipJavaDBUpdate() bool {
	val, ok := c.Data[keyVulSkipJavaDBUpdate]
	if !ok {
		return false
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return boolVal
}

func (c Config) GetServerInsecure() bool {
	_, ok := c.Data[keyVulServerInsecure]
	return ok
}

func (c Config) GetDBRepositoryInsecure() bool {
	val, ok := c.Data[keyVulDBRepositoryInsecure]
	if !ok {
		return false
	}
	boolVal, _ := strconv.ParseBool(val)
	return boolVal
}
func (c Config) GetUseBuiltinRegoPolicies() bool {
	val, ok := c.Data[keyVulUseBuiltinRegoPolicies]
	if !ok {
		return true
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return true
	}
	return boolVal
}
func (c Config) GetSslCertDir() string {
	val, ok := c.Data[keyVulSslCertDir]
	if !ok {
		return ""
	}
	return val
}

func (c Config) GetSeverity() string {
	val, ok := c.Data[KeyVulSeverity]
	if !ok {
		return ""
	}
	return val
}

func (c Config) GetSlow() bool {
	val, ok := c.Data[keyVulSlow]
	if !ok {
		return true
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return true
	}
	return boolVal
}

func (c Config) GetVulnType() string {
	val, ok := c.Data[keyVulVulnType]
	if !ok {
		return ""
	}
	trimmedVulnType := strings.TrimSpace(val)
	if !(trimmedVulnType == "os" || trimmedVulnType == "library") {
		return ""
	}
	return trimmedVulnType
}

func (c Config) GetSupportedConfigAuditKinds() []string {
	val, ok := c.Data[keyVulSupportedConfigAuditKinds]
	if !ok {
		return utils.MapKinds(strings.Split(SupportedConfigAuditKinds, ","))
	}
	return utils.MapKinds(strings.Split(val, ","))
}

func (c Config) IgnoreFileExists() bool {
	_, ok := c.Data[keyVulIgnoreFile]
	return ok
}

func (c Config) FindIgnorePolicyKey(workload client.Object) string {
	keysByPrecedence := []string{
		keyVulIgnorePolicy + "." + workload.GetNamespace() + "." + workload.GetName(),
		keyVulIgnorePolicy + "." + workload.GetNamespace(),
		keyVulIgnorePolicy,
	}
	for _, key := range keysByPrecedence {
		for key2 := range c.Data {
			if key2 == keyVulIgnorePolicy || strings.HasPrefix(key2, keyVulIgnorePolicy) {
				tempKey := key2
				if key2 != keyVulIgnorePolicy {
					// replace dot with astrix for regex matching
					tempKey = fmt.Sprintf("%s%s", keyVulIgnorePolicy, strings.ReplaceAll(tempKey[len(keyVulIgnorePolicy):], ".", "*"))
				}
				matched, err := filepath.Match(tempKey, key)
				if err == nil && matched {
					return key2
				}
			}
		}
	}
	return ""
}

func (c Config) GenerateIgnoreFileVolumeIfAvailable(vulConfigName string) (*corev1.Volume, *corev1.VolumeMount) {
	if !c.IgnoreFileExists() {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: ignoreFileVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: vulConfigName,
				},
				Items: []corev1.KeyToPath{
					{
						Key:  keyVulIgnoreFile,
						Path: ignoreFileName,
					},
				},
			},
		},
	}
	volumeMount := corev1.VolumeMount{
		Name:      ignoreFileVolumeName,
		MountPath: ignoreFileMountPath,
		SubPath:   ignoreFileName,
	}
	return &volume, &volumeMount
}

func (c Config) GenerateSslCertDirVolumeIfAvailable(vulConfigName string) (*corev1.Volume, *corev1.VolumeMount) {
	var sslCertDirHost string
	if sslCertDirHost = c.GetSslCertDir(); len(sslCertDirHost) == 0 {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: sslCertDirVolumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: sslCertDirHost,
			},
		},
	}
	volumeMount := corev1.VolumeMount{
		Name:      sslCertDirVolumeName,
		MountPath: SslCertDir,
		ReadOnly:  true,
	}
	return &volume, &volumeMount
}

func (c Config) GenerateIgnorePolicyVolumeIfAvailable(vulConfigName string, workload client.Object) (*corev1.Volume, *corev1.VolumeMount) {
	ignorePolicyKey := c.FindIgnorePolicyKey(workload)
	if ignorePolicyKey == "" {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: ignorePolicyVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: vulConfigName,
				},
				Items: []corev1.KeyToPath{
					{
						Key:  c.FindIgnorePolicyKey(workload),
						Path: ignorePolicyName,
					},
				},
			},
		},
	}
	volumeMounts := corev1.VolumeMount{
		Name:      ignorePolicyVolumeName,
		MountPath: ignorePolicyMountPath,
		SubPath:   ignorePolicyName,
	}
	return &volume, &volumeMounts
}

func (c Config) IgnoreUnfixed() bool {
	_, ok := c.Data[keyVulIgnoreUnfixed]
	return ok
}

func (c Config) OfflineScan() bool {
	_, ok := c.Data[keyVulOfflineScan]
	return ok
}

func (c Config) GetInsecureRegistries() map[string]bool {
	insecureRegistries := make(map[string]bool)
	for key, val := range c.Data {
		if strings.HasPrefix(key, keyVulInsecureRegistryPrefix) {
			insecureRegistries[val] = true
		}
	}

	return insecureRegistries
}

func (c Config) GetNonSSLRegistries() map[string]bool {
	nonSSLRegistries := make(map[string]bool)
	for key, val := range c.Data {
		if strings.HasPrefix(key, keyVulNonSslRegistryPrefix) {
			nonSSLRegistries[val] = true
		}
	}

	return nonSSLRegistries
}

func (c Config) GetMirrors() map[string]string {
	res := make(map[string]string)
	for registryKey, mirror := range c.Data {
		if !strings.HasPrefix(registryKey, keyVulMirrorPrefix) {
			continue
		}
		res[strings.TrimPrefix(registryKey, keyVulMirrorPrefix)] = mirror
	}
	return res
}

// GetResourceRequirements creates ResourceRequirements from the Config.
func (c Config) GetResourceRequirements() (corev1.ResourceRequirements, error) {
	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	err := c.setResourceLimit(keyResourcesRequestsCPU, &requirements.Requests, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesRequestsMemory, &requirements.Requests, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesRequestEphemeralStorage, &requirements.Requests, corev1.ResourceEphemeralStorage)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitEphemeralStorage, &requirements.Limits, corev1.ResourceEphemeralStorage)
	if err != nil {
		return requirements, err
	}

	return requirements, nil
}

func (c Config) setResourceLimit(configKey string, k8sResourceList *corev1.ResourceList, k8sResourceName corev1.ResourceName) error {
	if value, found := c.Data[configKey]; found {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return fmt.Errorf("parsing resource definition %s: %s %w", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

func (c Config) GetDBRepository() (string, error) {
	return c.GetRequiredData(keyVulDBRepository)
}

type plugin struct {
	clock          ext.Clock
	idGenerator    ext.IDGenerator
	objectResolver *kube.ObjectResolver
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using an
// upstream Vul container image to scan Kubernetes workloads.
//
// The plugin supports Image and Filesystem commands. The Filesystem command may
// be used to scan workload images cached on cluster nodes by scheduling
// scan jobs on a particular node.
//
// The Image command supports both Standalone and ClientServer modes depending
// on the settings returned by Config.GetMode. The ClientServer mode is usually
// more performant, however it requires a Vul server accessible at the
// configurable Config.GetServerURL.
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, objectResolver *kube.ObjectResolver) vulnerabilityreport.Plugin {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
	}
}

// NewVulConfigAuditPlugin constructs a new configAudit.Plugin, which is using an
// upstream Vul config audit scanner lib.
func NewVulConfigAuditPlugin(clock ext.Clock, idGenerator ext.IDGenerator, objectResolver *kube.ObjectResolver) configauditreport.PluginInMemory {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
	}
}

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx vuloperator.PluginContext) error {
	return ctx.EnsureConfig(vuloperator.PluginConfig{
		Data: map[string]string{
			keyVulImageRepository:           DefaultImageRepository,
			keyVulImageTag:                  "0.45.1",
			KeyVulSeverity:                  DefaultSeverity,
			keyVulSlow:                      "true",
			keyVulMode:                      string(Standalone),
			keyVulTimeout:                   "5m0s",
			keyVulDBRepository:              DefaultDBRepository,
			keyVulJavaDBRepository:          DefaultJavaDBRepository,
			keyVulUseBuiltinRegoPolicies:    "true",
			keyVulSupportedConfigAuditKinds: SupportedConfigAuditKinds,
			keyResourcesRequestsCPU:           "100m",
			keyResourcesRequestsMemory:        "100M",
			keyResourcesLimitsCPU:             "500m",
			keyResourcesLimitsMemory:          "500M",
		},
	})
}

func (p *plugin) GetScanJobSpec(ctx vuloperator.PluginContext, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	mode, err := config.GetMode()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	command, err := config.GetCommand()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	var podSpec corev1.PodSpec
	var secrets []*corev1.Secret
	if command == Image {
		switch mode {
		case Standalone:
			podSpec, secrets, err = p.getPodSpecForStandaloneMode(ctx, config, workload, credentials, securityContext)
		case ClientServer:
			podSpec, secrets, err = p.getPodSpecForClientServerMode(ctx, config, workload, credentials, securityContext)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized vul mode %q for command %q", mode, command)
		}
	}
	if command == Filesystem || command == Rootfs {
		switch mode {
		case Standalone:
			podSpec, secrets, err = p.getPodSpecForStandaloneFSMode(ctx, command, config, workload, securityContext)
		case ClientServer:
			podSpec, secrets, err = p.getPodSpecForClientServerFSMode(ctx, command, config, workload, securityContext)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized vul mode %q for command %q", mode, command)
		}
	}
	// add image pull secret to be used when pulling vul image fom private registry
	podSpec.ImagePullSecrets = config.GetImagePullSecret()
	return podSpec, secrets, err
}

func (p *plugin) newSecretWithAggregateImagePullCredentials(obj client.Object, containerImages kube.ContainerImages, credentials map[string]docker.Auth) *corev1.Secret {
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: vulnerabilityreport.RegistryCredentialsSecretName(obj),
		},
		Data: secretData,
	}
}

const (
	tmpVolumeName               = "tmp"
	ignoreFileVolumeName        = "ignorefile"
	sslCertDirVolumeName        = "ssl-cert-dir"
	ignoreFileName              = ".vulignore"
	ignoreFileMountPath         = "/etc/vul/" + ignoreFileName
	ignorePolicyVolumeName      = "ignorepolicy"
	ignorePolicyName            = "policy.rego"
	ignorePolicyMountPath       = "/etc/vul/" + ignorePolicyName
	scanResultVolumeName        = "scanresult"
	FsSharedVolumeName          = "vuloperator"
	SharedVolumeLocationOfVul = "/var/vuloperator/vul"
	SslCertDir                  = "/var/ssl-cert"
)

// In the Standalone mode there is the init container responsible for
// downloading the latest Vul DB file from GitHub and storing it to the
// emptyDir volume shared with main containers. In other words, the init
// container runs the following Vul command:
//
//	vul --cache-dir /tmp/vul/.cache image --download-db-only
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. Each container runs the Vul image scan
// command and skips the database download:
//
//	vul --cache-dir /tmp/vul/.cache image --skip-update \
//	  --format json <container image>
func (p *plugin) getPodSpecForStandaloneMode(ctx vuloperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var containersSpec []corev1.Container

	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	for _, c := range getContainers(spec) {
		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		c.Image = optionalMirroredImage
		containersSpec = append(containersSpec, c)
	}

	containerImages := kube.GetContainerImagesFromContainersList(containersSpec)
	containersCredentials, err := kube.MapContainerNamesToDockerAuths(containerImages, credentials)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	if len(containersCredentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, containerImages, containersCredentials)
		secrets = append(secrets, secret)
	}

	vulImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	vulConfigName := vuloperator.GetPluginConfigMapName(Plugin)

	dbRepository, err := config.GetDBRepository()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	initContainer := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    vulImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      p.initContainerEnvVar(vulConfigName, config),
		Command: []string{
			"vul",
		},
		Args: []string{
			"--cache-dir",
			"/tmp/vul/.cache",
			"image",
			"--download-db-only",
			"--db-repository",
			dbRepository,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      tmpVolumeName,
				MountPath: "/tmp",
				ReadOnly:  false,
			},
		},
	}

	var containers []corev1.Container

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      tmpVolumeName,
			ReadOnly:  false,
			MountPath: "/tmp",
		},
	}
	volumes := []corev1.Volume{
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}
	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(vulConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, c := range containersSpec {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("VUL_SEVERITY", vulConfigName, KeyVulSeverity),
			constructEnvVarSourceFromConfigMap("VUL_IGNORE_UNFIXED", vulConfigName, keyVulIgnoreUnfixed),
			constructEnvVarSourceFromConfigMap("VUL_OFFLINE_SCAN", vulConfigName, keyVulOfflineScan),
			constructEnvVarSourceFromConfigMap("VUL_JAVA_DB_REPOSITORY", vulConfigName, keyVulJavaDBRepository),
			constructEnvVarSourceFromConfigMap("VUL_TIMEOUT", vulConfigName, keyVulTimeout),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "VUL_SKIP_FILES", vulConfigName, keyVulSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "VUL_SKIP_DIRS", vulConfigName, keyVulSkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
		}

		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}

		region := CheckAwsEcrPrivateRegistry(c.Image)
		if region != "" {
			env = append(env, corev1.EnvVar{
				Name:  "AWS_REGION",
				Value: region,
			})
		}
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_INSECURE",
				Value: "true",
			})
		}
		gcrImage := checkGcpCrOrPivateRegistry(c.Image)
		if _, ok := containersCredentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)
			secretName := secret.Name
			if gcrImage {
				createEnvandVolumeForGcr(&env, &volumeMounts, &volumes, &registryPasswordKey, &secretName)
			} else {
				env = append(env, corev1.EnvVar{
					Name: "VUL_USERNAME",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: secret.Name,
							},
							Key: registryUsernameKey,
						},
					},
				}, corev1.EnvVar{
					Name: "VUL_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: secret.Name,
							},
							Key: registryPasswordKey,
						},
					},
				})
			}

		}

		env, err = p.appendVulInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = p.appendVulNonSSLEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		imageRef, err := containerimage.ParseReference(c.Image)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		resultFileName := getUniqueScanResultFileName(c.Name)
		cmd, args := p.getCommandAndArgs(ctx, Standalone, imageRef.String(), "", resultFileName)
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    vulImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  cmd,
			Args:                     args,
			Resources:                resourceRequirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	return corev1.PodSpec{
		Affinity:                     vuloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainer},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

func checkGcpCrOrPivateRegistry(imageUrl string) bool {
	imageRegex := regexp.MustCompile(GCPCR_Inage_Regex)
	return imageRegex.MatchString(imageUrl)
}

func (p *plugin) initContainerEnvVar(vulConfigName string, config Config) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
		constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
		constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
		constructEnvVarSourceFromSecret("GITHUB_TOKEN", vulConfigName, keyVulGitHubToken),
	}

	if config.GetDBRepositoryInsecure() {
		envs = append(envs, corev1.EnvVar{
			Name:  "VUL_INSECURE",
			Value: "true",
		})
	}
	return envs
}

// In the ClientServer mode the number of containers of the pod created by the
// scan job equals the number of containers defined for the scanned workload.
// Each container runs Vul image scan command and refers to Vul server URL
// returned by Config.GetServerURL:
//
//	vul image --server <server URL> \
//	  --format json <container image>
func (p *plugin) getPodSpecForClientServerMode(ctx vuloperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var containersSpec []corev1.Container
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	vulImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	vulServerURL, err := config.GetServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	for _, c := range getContainers(spec) {
		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		c.Image = optionalMirroredImage
		containersSpec = append(containersSpec, c)
	}

	containerImages := kube.GetContainerImagesFromContainersList(containersSpec)
	containersCredentials, err := kube.MapContainerNamesToDockerAuths(containerImages, credentials)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	if len(containersCredentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, containerImages, containersCredentials)
		secrets = append(secrets, secret)
	}

	var containers []corev1.Container

	vulConfigName := vuloperator.GetPluginConfigMapName(Plugin)
	// add tmp volume mount
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      tmpVolumeName,
			ReadOnly:  false,
			MountPath: "/tmp",
		},
	}

	// add tmp volume
	volumes := []corev1.Volume{
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(vulConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, container := range containersSpec {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
			constructEnvVarSourceFromConfigMap("VUL_SEVERITY", vulConfigName, KeyVulSeverity),
			constructEnvVarSourceFromConfigMap("VUL_IGNORE_UNFIXED", vulConfigName, keyVulIgnoreUnfixed),
			constructEnvVarSourceFromConfigMap("VUL_OFFLINE_SCAN", vulConfigName, keyVulOfflineScan),
			constructEnvVarSourceFromConfigMap("VUL_JAVA_DB_REPOSITORY", vulConfigName, keyVulJavaDBRepository),
			constructEnvVarSourceFromConfigMap("VUL_TIMEOUT", vulConfigName, keyVulTimeout),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "VUL_SKIP_FILES", vulConfigName, keyVulSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "VUL_SKIP_DIRS", vulConfigName, keyVulSkipDirs),
			constructEnvVarSourceFromConfigMap("VUL_TOKEN_HEADER", vulConfigName, keyVulServerTokenHeader),
			constructEnvVarSourceFromSecret("VUL_TOKEN", vulConfigName, keyVulServerToken),
			constructEnvVarSourceFromSecret("VUL_CUSTOM_HEADERS", vulConfigName, keyVulServerCustomHeaders),
		}
		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}

		if auth, ok := containersCredentials[container.Name]; ok && secret != nil {
			if checkGcpCrOrPivateRegistry(container.Image) && auth.Username == "_json_key" {
				registryServiceAccountAuthKey := fmt.Sprintf("%s.password", container.Name)
				createEnvandVolumeForGcr(&env, &volumeMounts, &volumes, &registryServiceAccountAuthKey, &secret.Name)
			} else {
				registryUsernameKey := fmt.Sprintf("%s.username", container.Name)
				registryPasswordKey := fmt.Sprintf("%s.password", container.Name)
				env = append(env, corev1.EnvVar{
					Name: "VUL_USERNAME",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: secret.Name,
							},
							Key: registryUsernameKey,
						},
					},
				}, corev1.EnvVar{
					Name: "VUL_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: secret.Name,
							},
							Key: registryPasswordKey,
						},
					},
				})
			}
		}

		env, err = p.appendVulInsecureEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = p.appendVulNonSSLEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_INSECURE",
				Value: "true",
			})
		}

		requirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		encodedVulServerURL, err := url.Parse(vulServerURL)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		imageRef, err := containerimage.ParseReference(container.Image)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		resultFileName := getUniqueScanResultFileName(container.Name)
		cmd, args := p.getCommandAndArgs(ctx, ClientServer, imageRef.String(), encodedVulServerURL.String(), resultFileName)
		containers = append(containers, corev1.Container{
			Name:                     container.Name,
			Image:                    vulImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  cmd,
			Args:                     args,
			Resources:                requirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	return corev1.PodSpec{
		Affinity:                     vuloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Containers:                   containers,
		Volumes:                      volumes,
	}, secrets, nil
}

func (p *plugin) getCommandAndArgs(ctx vuloperator.PluginContext, mode Mode, imageRef string, vulServerURL string, resultFileName string) ([]string, []string) {
	command := []string{
		"vul",
	}
	vulConfig := ctx.GetVulOperatorConfig()
	compressLogs := vulConfig.CompressLogs()
	c, err := p.getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)
	skipJavaDBUpdate := SkipJavaDBUpdate(c)
	vulnTypeArgs := p.vulnTypeFilter(ctx)
	scanners := Scanners(c)
	var vulnTypeFlag string
	if len(vulnTypeArgs) == 2 {
		vulnTypeFlag = fmt.Sprintf("%s %s ", vulnTypeArgs[0], vulnTypeArgs[1])
	}
	imcs := p.imageConfigSecretScanner(vulConfig)
	var imageconfigSecretScannerFlag string
	if len(imcs) == 2 {
		imageconfigSecretScannerFlag = fmt.Sprintf("%s %s ", imcs[0], imcs[1])
	}
	var skipUpdate string
	if mode == ClientServer {
		if c.GetClientServerSkipUpdate() {
			skipUpdate = SkipDBUpdate(c)
		}
		if !compressLogs {
			args := []string{
				"--cache-dir",
				"/tmp/vul/.cache",
				"--quiet",
				"image",
				scanners,
				getSecurityChecks(ctx),
				"--format",
				"json",
				"--server",
				vulServerURL,
				imageRef,
			}
			if len(slow) > 0 {
				args = append(args, slow)
			}
			if len(vulnTypeArgs) > 0 {
				args = append(args, vulnTypeArgs...)
			}
			if len(imcs) > 0 {
				args = append(args, imcs...)
			}
			pkgList := getPkgList(ctx)
			if len(pkgList) > 0 {
				args = append(args, pkgList)
			}
			if len(skipUpdate) > 0 {
				args = append(args, skipUpdate)
			}
			if len(skipJavaDBUpdate) > 0 {
				args = append(args, skipJavaDBUpdate)
			}

			return command, args
		}
		return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`vul image %s '%s' %s %s %s %s %s %s --cache-dir /tmp/vul/.cache --quiet %s --format json --server '%s' > /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, getPkgList(ctx), vulServerURL, resultFileName, resultFileName)}
	}
	skipUpdate = SkipDBUpdate(c)
	if !compressLogs {
		args := []string{
			"--cache-dir",
			"/tmp/vul/.cache",
			"--quiet",
			"image",
			scanners,
			getSecurityChecks(ctx),
			"--format",
			"json",
			imageRef,
		}
		if len(slow) > 0 {
			args = append(args, slow)
		}
		if len(vulnTypeArgs) > 0 {
			args = append(args, vulnTypeArgs...)
		}
		if len(imcs) > 0 {
			args = append(args, imcs...)
		}
		pkgList := getPkgList(ctx)
		if len(pkgList) > 0 {
			args = append(args, pkgList)
		}
		if len(skipUpdate) > 0 {
			args = append(args, skipUpdate)
		}
		if len(skipJavaDBUpdate) > 0 {
			args = append(args, skipJavaDBUpdate)
		}
		return command, args
	}
	return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`vul image %s '%s' %s %s %s %s %s %s --cache-dir /tmp/vul/.cache --quiet %s --format json > /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, getPkgList(ctx), resultFileName, resultFileName)}
}

func (p *plugin) vulnTypeFilter(ctx vuloperator.PluginContext) []string {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return []string{}
	}
	vulnType := config.GetVulnType()
	if len(vulnType) == 0 {
		return []string{}
	}
	return []string{"--vuln-type", vulnType}
}

func (p *plugin) imageConfigSecretScanner(tc vuloperator.ConfigData) []string {

	if tc.ExposedSecretsScannerEnabled() {
		return []string{"--image-config-scanners", "secret"}
	}
	return []string{}
}

func getAutomountServiceAccountToken(ctx vuloperator.PluginContext) bool {
	return ctx.GetVulOperatorConfig().GetScanJobAutomountServiceAccountToken()
}
func getUniqueScanResultFileName(name string) string {
	return fmt.Sprintf("result_%s.json", name)
}

func getScanResultVolume() corev1.Volume {
	return corev1.Volume{
		Name: scanResultVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}
}

func getScanResultVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      scanResultVolumeName,
		ReadOnly:  false,
		MountPath: "/tmp/scan",
	}
}

func createEnvandVolumeForGcr(env *[]corev1.EnvVar, volumeMounts *[]corev1.VolumeMount, volumes *[]corev1.Volume, registryPasswordKey *string, secretName *string) {
	*env = append(*env, corev1.EnvVar{
		Name:  "VUL_USERNAME",
		Value: "",
	})
	*env = append(*env, corev1.EnvVar{
		Name:  "GOOGLE_APPLICATION_CREDENTIALS",
		Value: "/cred/credential.json",
	})
	googlecredMount := corev1.VolumeMount{
		Name:      "gcrvol",
		MountPath: "/cred",
		ReadOnly:  true,
	}
	googlecredVolume := corev1.Volume{
		Name: "gcrvol",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: *secretName,
				Items: []corev1.KeyToPath{
					{
						Key:  *registryPasswordKey,
						Path: "credential.json",
					},
				},
			},
		},
	}
	*volumes = append(*volumes, googlecredVolume)
	*volumeMounts = append(*volumeMounts, googlecredMount)
}

// FileSystem scan option with standalone mode.
// The only difference is that instead of scanning the resource by name,
// We are scanning the resource place on a specific file system location using the following command.
//
//	vul --quiet fs  --format json --ignore-unfixed  file/system/location
func (p *plugin) getPodSpecForStandaloneFSMode(ctx vuloperator.PluginContext, command Command, config Config,
	workload client.Object, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secrets []*corev1.Secret
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	pullPolicy := corev1.PullIfNotPresent
	// nodeName to schedule scan job explicitly on specific node.
	var nodeName string
	if !ctx.GetVulOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// get nodeName from running pods.
		nodeName, err = p.objectResolver.GetNodeName(context.Background(), workload)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed resolving node name for workload %q: %w",
				workload.GetNamespace()+"/"+workload.GetName(), err)
		}
		pullPolicy = corev1.PullNever
	}

	vulImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	vulConfigName := vuloperator.GetPluginConfigMapName(Plugin)

	dbRepository, err := config.GetDBRepository()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      FsSharedVolumeName,
			ReadOnly:  false,
			MountPath: "/var/vuloperator",
		},
		{
			Name:      tmpVolumeName,
			MountPath: "/tmp",
			ReadOnly:  false,
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    vulImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/vul",
			SharedVolumeLocationOfVul,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
	}

	initContainerDB := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    vulImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      p.initContainerFSEnvVar(vulConfigName, config),
		Command: []string{
			"vul",
		},
		Args: []string{
			"--cache-dir",
			"/var/vuloperator/vul-db",
			"image",
			"--download-db-only",
			"--db-repository",
			dbRepository,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
	}

	var containers []corev1.Container

	volumes := []corev1.Volume{
		{
			Name: FsSharedVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(vulConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, c := range getContainers(spec) {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("VUL_SEVERITY", vulConfigName, KeyVulSeverity),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "VUL_SKIP_FILES", vulConfigName, keyVulSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "VUL_SKIP_DIRS", vulConfigName, keyVulSkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
			constructEnvVarSourceFromConfigMap("VUL_JAVA_DB_REPOSITORY", vulConfigName, keyVulJavaDBRepository),
		}
		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("VUL_IGNORE_UNFIXED",
				vulConfigName, keyVulIgnoreUnfixed))
		}
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_INSECURE",
				Value: "true",
			})
		}

		if config.OfflineScan() {
			env = append(env, constructEnvVarSourceFromConfigMap("VUL_OFFLINE_SCAN",
				vulConfigName, keyVulOfflineScan))
		}

		env, err = p.appendVulInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    c.Image,
			ImagePullPolicy:          pullPolicy,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				SharedVolumeLocationOfVul,
			},
			Args:            p.getFSScanningArgs(ctx, command, Standalone, ""),
			Resources:       resourceRequirements,
			SecurityContext: securityContext,
			VolumeMounts:    volumeMounts,
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     vuloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainerCopyBinary, initContainerDB},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}

	if !ctx.GetVulOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// schedule scan job explicitly on specific node.
		podSpec.NodeName = nodeName
	}

	return podSpec, secrets, nil
}

// FileSystem scan option with ClientServer mode.
// The only difference is that instead of scanning the resource by name,
// We scanning the resource place on a specific file system location using the following command.
//
//	vul --quiet fs  --server VUL_SERVER  --format json --ignore-unfixed  file/system/location
func (p *plugin) getPodSpecForClientServerFSMode(ctx vuloperator.PluginContext, command Command, config Config,
	workload client.Object, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	var secrets []*corev1.Secret
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	pullPolicy := corev1.PullIfNotPresent
	// nodeName to schedule scan job explicitly on specific node.
	var nodeName string
	if !ctx.GetVulOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// get nodeName from running pods.
		nodeName, err = p.objectResolver.GetNodeName(context.Background(), workload)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed resolving node name for workload %q: %w",
				workload.GetNamespace()+"/"+workload.GetName(), err)
		}
		pullPolicy = corev1.PullNever
	}

	vulImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	vulServerURL, err := config.GetServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	encodedVulServerURL, err := url.Parse(vulServerURL)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	vulConfigName := vuloperator.GetPluginConfigMapName(Plugin)

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      FsSharedVolumeName,
			ReadOnly:  false,
			MountPath: "/var/vuloperator",
		},
		{
			Name:      tmpVolumeName,
			MountPath: "/tmp",
			ReadOnly:  false,
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    vulImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/vul",
			SharedVolumeLocationOfVul,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
	}

	var containers []corev1.Container

	volumes := []corev1.Volume{
		{
			Name: FsSharedVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}
	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(vulConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(vulConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, c := range getContainers(spec) {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("VUL_SEVERITY", vulConfigName, KeyVulSeverity),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "VUL_SKIP_FILES", vulConfigName, keyVulSkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "VUL_SKIP_DIRS", vulConfigName, keyVulSkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
			constructEnvVarSourceFromConfigMap("VUL_TOKEN_HEADER", vulConfigName, keyVulServerTokenHeader),
			constructEnvVarSourceFromSecret("VUL_TOKEN", vulConfigName, keyVulServerToken),
			constructEnvVarSourceFromSecret("VUL_CUSTOM_HEADERS", vulConfigName, keyVulServerCustomHeaders),
			constructEnvVarSourceFromConfigMap("VUL_JAVA_DB_REPOSITORY", vulConfigName, keyVulJavaDBRepository),
		}
		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("VUL_IGNORE_UNFIXED",
				vulConfigName, keyVulIgnoreUnfixed))
		}

		if config.OfflineScan() {
			env = append(env, constructEnvVarSourceFromConfigMap("VUL_OFFLINE_SCAN",
				vulConfigName, keyVulOfflineScan))
		}

		env, err = p.appendVulInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_INSECURE",
				Value: "true",
			})
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    c.Image,
			ImagePullPolicy:          pullPolicy,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				SharedVolumeLocationOfVul,
			},
			Args:            p.getFSScanningArgs(ctx, command, ClientServer, encodedVulServerURL.String()),
			Resources:       resourceRequirements,
			SecurityContext: securityContext,
			VolumeMounts:    volumeMounts,
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     vuloperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.Bool(getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainerCopyBinary},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}

	if !ctx.GetVulOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// schedule scan job explicitly on specific node.
		podSpec.NodeName = nodeName
	}

	return podSpec, secrets, nil
}

func (p *plugin) getFSScanningArgs(ctx vuloperator.PluginContext, command Command, mode Mode, vulServerURL string) []string {
	c, err := p.getConfig(ctx)
	if err != nil {
		return []string{}
	}
	scanners := Scanners(c)
	imcs := p.imageConfigSecretScanner(c.Data)
	skipUpdate := SkipDBUpdate(c)
	args := []string{
		"--cache-dir",
		"/var/vuloperator/vul-db",
		"--quiet",
		string(command),
		scanners,
		getSecurityChecks(ctx),
		skipUpdate,
		"--format",
		"json",
		"/",
	}
	if len(imcs) > 0 {
		args = append(args, imcs...)
	}
	if mode == ClientServer {
		args = append(args, "--server", vulServerURL)
	}
	slow := Slow(c)
	if len(slow) > 0 {
		args = append(args, slow)
	}
	pkgList := getPkgList(ctx)
	if len(pkgList) > 0 {
		args = append(args, pkgList)
	}
	return args
}

func (p *plugin) initContainerFSEnvVar(vulConfigName string, config Config) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
		constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
		constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
		constructEnvVarSourceFromSecret("GITHUB_TOKEN", vulConfigName, keyVulGitHubToken),
	}
	if config.GetDBRepositoryInsecure() {
		envs = append(envs, corev1.EnvVar{
			Name:  "VUL_INSECURE",
			Value: "true",
		})
	}
	return envs
}

func (p *plugin) appendVulInsecureEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := containerimage.ParseReference(image)
	if err != nil {
		return nil, err
	}

	insecureRegistries := config.GetInsecureRegistries()
	if insecureRegistries[ref.Context().RegistryStr()] {
		env = append(env, corev1.EnvVar{
			Name:  "VUL_INSECURE",
			Value: "true",
		})
	}

	return env, nil
}

func (p *plugin) appendVulNonSSLEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := containerimage.ParseReference(image)
	if err != nil {
		return nil, err
	}

	nonSSLRegistries := config.GetNonSSLRegistries()
	if nonSSLRegistries[ref.Context().RegistryStr()] {
		env = append(env, corev1.EnvVar{
			Name:  "VUL_NON_SSL",
			Value: "true",
		})
	}

	return env, nil
}

func (p *plugin) ParseReportData(ctx vuloperator.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, v1alpha1.ExposedSecretReportData, *v1alpha1.SbomReportData, error) {
	var vulnReport v1alpha1.VulnerabilityReportData
	var secretReport v1alpha1.ExposedSecretReportData
	var sbomReport v1alpha1.SbomReportData

	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	cmd, err := config.GetCommand()
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	compressedLogs := ctx.GetVulOperatorConfig().CompressLogs()
	if compressedLogs && cmd != Filesystem && cmd != Rootfs {
		var errCompress error
		logsReader, errCompress = utils.ReadCompressData(logsReader)
		if errCompress != nil {
			return vulnReport, secretReport, &sbomReport, errCompress
		}
	}

	var reports ty.Report
	err = json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	vulnerabilities := make([]v1alpha1.Vulnerability, 0)
	secrets := make([]v1alpha1.ExposedSecret, 0)
	addFields := config.GetAdditionalVulnerabilityReportFields()

	for _, report := range reports.Results {
		vulnerabilities = append(vulnerabilities, getVulnerabilitiesFromScanResult(report, addFields)...)
		secrets = append(secrets, getExposedSecretsFromScanResult(report)...)
	}
	var bom *v1alpha1.BOM
	if ctx.GetVulOperatorConfig().GenerateSbomEnabled() {
		bom, err = generateSbomFromScanResult(reports)
		if err != nil {
			return vulnReport, secretReport, &sbomReport, err
		}
	}
	registry, artifact, err := p.parseImageRef(imageRef, reports.Metadata.ImageID)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	vulImageRef, err := config.GetImageRef()
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	version, err := vuloperator.GetVersionFromImageRef(vulImageRef)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	var sbomData *v1alpha1.SbomReportData
	if bom != nil {
		sbomData = &v1alpha1.SbomReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameVul,
				Vendor:  "Khulnasoft Security",
				Version: version,
			},
			Registry: registry,
			Artifact: artifact,
			Summary:  bomSummary(*bom),
			Bom:      *bom,
		}
	}
	return v1alpha1.VulnerabilityReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameVul,
				Vendor:  "Khulnasoft Security",
				Version: version,
			},
			Registry:        registry,
			Artifact:        artifact,
			Summary:         p.vulnerabilitySummary(vulnerabilities),
			Vulnerabilities: vulnerabilities,
		}, v1alpha1.ExposedSecretReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameVul,
				Vendor:  "Khulnasoft Security",
				Version: version,
			},
			Registry: registry,
			Artifact: artifact,
			Summary:  p.secretSummary(secrets),
			Secrets:  secrets,
		}, sbomData, nil

}

func bomSummary(bom v1alpha1.BOM) v1alpha1.SbomSummary {
	return v1alpha1.SbomSummary{
		ComponentsCount:   len(bom.Components) + 1,
		DependenciesCount: len(*bom.Dependencies),
	}

}

func getVulnerabilitiesFromScanResult(report ty.Result, addFields AdditionalFields) []v1alpha1.Vulnerability {
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, sr := range report.Vulnerabilities {
		var pd, lmd string
		if sr.PublishedDate != nil {
			pd = sr.PublishedDate.Format(time.RFC3339)
		}
		if sr.LastModifiedDate != nil {
			lmd = sr.LastModifiedDate.Format(time.RFC3339)
		}
		vulnerability := v1alpha1.Vulnerability{
			VulnerabilityID:  sr.VulnerabilityID,
			Resource:         sr.PkgName,
			InstalledVersion: sr.InstalledVersion,
			FixedVersion:     sr.FixedVersion,
			PublishedDate:    pd,
			LastModifiedDate: lmd,
			Severity:         v1alpha1.Severity(sr.Severity),
			Title:            sr.Title,
			PrimaryLink:      sr.PrimaryURL,
			Links:            []string{},
			Score:            GetScoreFromCVSS(GetCvssV3(sr.CVSS)),
		}

		if addFields.Description {
			vulnerability.Description = sr.Description
		}
		if addFields.Links && sr.References != nil {
			vulnerability.Links = sr.References
		}
		if addFields.CVSS {
			vulnerability.CVSS = sr.CVSS
		}
		if addFields.Target {
			vulnerability.Target = report.Target
		}
		if addFields.Class {
			vulnerability.Class = string(report.Class)
		}
		if addFields.PackageType {
			vulnerability.PackageType = report.Type
		}
		if addFields.PkgPath {
			vulnerability.PkgPath = sr.PkgPath
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	return vulnerabilities
}

func generateSbomFromScanResult(report ty.Report) (*v1alpha1.BOM, error) {
	var bom *v1alpha1.BOM
	if len(report.Results) > 0 && len(report.Results[0].Packages) > 0 {
		// capture os.Stdout with a writer
		done := capture()
		err := tr.Write(report, fg.Options{
			ReportOptions: fg.ReportOptions{
				Format: ty.FormatCycloneDX,
			},
		})
		if err != nil {
			return nil, err
		}
		bomWriter, err := done()
		if err != nil {
			return nil, err
		}
		var bom cdx.BOM
		err = json.Unmarshal([]byte(bomWriter), &bom)
		if err != nil {
			return nil, err
		}
		return cycloneDxBomToReport(bom), nil
	}
	return bom, nil
}

func getExposedSecretsFromScanResult(report ty.Result) []v1alpha1.ExposedSecret {
	secrets := make([]v1alpha1.ExposedSecret, 0)

	for _, sr := range report.Secrets {
		secrets = append(secrets, v1alpha1.ExposedSecret{
			Target:   report.Target,
			RuleID:   sr.RuleID,
			Title:    sr.Title,
			Severity: v1alpha1.Severity(sr.Severity),
			Category: string(sr.Category),
			Match:    sr.Match,
		})
	}

	return secrets
}

func (p *plugin) newConfigFrom(ctx vuloperator.PluginContext) (Config, error) {
	return p.getConfig(ctx)
}

func (p *plugin) getConfig(ctx vuloperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

// NewConfigForConfigAudit and interface which expose related configaudit report configuration
func (p *plugin) NewConfigForConfigAudit(ctx vuloperator.PluginContext) (configauditreport.ConfigAuditConfig, error) {
	return p.getConfig(ctx)
}

func (p *plugin) vulnerabilitySummary(vulnerabilities []v1alpha1.Vulnerability) v1alpha1.VulnerabilitySummary {
	var vs v1alpha1.VulnerabilitySummary
	for _, v := range vulnerabilities {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			vs.CriticalCount++
		case v1alpha1.SeverityHigh:
			vs.HighCount++
		case v1alpha1.SeverityMedium:
			vs.MediumCount++
		case v1alpha1.SeverityLow:
			vs.LowCount++
		default:
			vs.UnknownCount++
		}
	}
	return vs
}

func (p *plugin) secretSummary(secrets []v1alpha1.ExposedSecret) v1alpha1.ExposedSecretSummary {
	var s v1alpha1.ExposedSecretSummary
	for _, v := range secrets {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			s.CriticalCount++
		case v1alpha1.SeverityHigh:
			s.HighCount++
		case v1alpha1.SeverityMedium:
			s.MediumCount++
		case v1alpha1.SeverityLow:
			s.LowCount++
		}
	}
	return s
}

func (p *plugin) parseImageRef(imageRef string, imageID string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
	ref, err := containerimage.ParseReference(imageRef)
	if err != nil {
		return v1alpha1.Registry{}, v1alpha1.Artifact{}, err
	}
	registry := v1alpha1.Registry{
		Server: ref.Context().RegistryStr(),
	}
	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case containerimage.Tag:
		artifact.Tag = t.TagStr()
	case containerimage.Digest:
		artifact.Digest = t.DigestStr()
	}
	if len(artifact.Digest) == 0 {
		artifact.Digest = imageID
	}
	return registry, artifact, nil
}

func GetCvssV3(findingCvss types.VendorCVSS) map[string]*CVSS {
	cvssV3 := make(map[string]*CVSS)
	for vendor, cvss := range findingCvss {
		var v3Score *float64
		if cvss.V3Score != 0.0 {
			v3Score = pointer.Float64(cvss.V3Score)
		}
		cvssV3[string(vendor)] = &CVSS{v3Score}
	}
	return cvssV3
}

func GetScoreFromCVSS(CVSSs map[string]*CVSS) *float64 {
	var nvdScore, vendorScore *float64

	for name, cvss := range CVSSs {
		if name == "nvd" {
			nvdScore = cvss.V3Score
		} else {
			vendorScore = cvss.V3Score
		}
	}

	if nvdScore != nil {
		return nvdScore
	}

	return vendorScore
}

func GetMirroredImage(image string, mirrors map[string]string) (string, error) {
	ref, err := containerimage.ParseReference(image)
	if err != nil {
		return "", err
	}
	mirroredImage := ref.Name()
	for k, v := range mirrors {
		if strings.HasPrefix(mirroredImage, k) {
			mirroredImage = strings.Replace(mirroredImage, k, v, 1)
			return mirroredImage, nil
		}
	}
	// If nothing is mirrored, we can simply use the input image.
	return image, nil
}

func constructEnvVarSourceFromConfigMap(envName, configName, configKey string) (res corev1.EnvVar) {
	res = corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configName,
				},
				Key:      configKey,
				Optional: pointer.Bool(true),
			},
		},
	}
	return
}

func constructEnvVarSourceFromSecret(envName, secretName, secretKey string) (res corev1.EnvVar) {
	res = corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: secretName,
				},
				Key:      secretKey,
				Optional: pointer.Bool(true),
			},
		},
	}
	return
}

func getContainers(spec corev1.PodSpec) []corev1.Container {
	containers := append(spec.Containers, spec.InitContainers...)

	// ephemeral container are not the same type as Containers/InitContainers,
	// then we add it in a different loop
	for _, c := range spec.EphemeralContainers {
		containers = append(containers, corev1.Container(c.EphemeralContainerCommon))
	}

	return containers
}

func CheckAwsEcrPrivateRegistry(ImageUrl string) string {
	if len(regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)) != 0 {
		return regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)[0][1]
	}
	return ""
}

func getSecurityChecks(ctx vuloperator.PluginContext) string {
	securityChecks := make([]string, 0)

	c := ctx.GetVulOperatorConfig()
	if c.VulnerabilityScannerEnabled() {
		securityChecks = append(securityChecks, "vuln")
	}

	if c.ExposedSecretsScannerEnabled() {
		securityChecks = append(securityChecks, "secret")
	}

	return strings.Join(securityChecks, ",")
}

func getPkgList(ctx vuloperator.PluginContext) string {
	c := ctx.GetVulOperatorConfig()
	if c.GenerateSbomEnabled() {
		return "--list-all-pkgs"
	}
	return ""
}

func ConfigWorkloadAnnotationEnvVars(workload client.Object, annotation string, envVarName string, vulConfigName string, configKey string) corev1.EnvVar {
	if value, ok := workload.GetAnnotations()[annotation]; ok {
		return corev1.EnvVar{
			Name:  envVarName,
			Value: value,
		}
	}
	return constructEnvVarSourceFromConfigMap(envVarName, vulConfigName, configKey)
}

type CVSS struct {
	V3Score *float64 `json:"V3Score,omitempty"`
}
