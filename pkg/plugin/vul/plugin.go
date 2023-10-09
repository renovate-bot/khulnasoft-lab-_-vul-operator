package vul

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/khulnasoft-lab/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft-lab/starboard/pkg/docker"
	"github.com/khulnasoft-lab/starboard/pkg/ext"
	"github.com/khulnasoft-lab/starboard/pkg/kube"
	"github.com/khulnasoft-lab/starboard/pkg/starboard"
	"github.com/khulnasoft-lab/starboard/pkg/vulnerabilityreport"
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
	AWSECR_Image_Regex = "^\\d+\\.dkr\\.ecr\\.(\\w+-\\w+-\\d+)\\.amazonaws\\.com\\/"
)

const (
	keyVulImageRef               = "vul.imageRef"
	keyVulMode                   = "vul.mode"
	keyVulCommand                = "vul.command"
	keyVulSeverity               = "vul.severity"
	keyVulIgnoreUnfixed          = "vul.ignoreUnfixed"
	keyVulTimeout                = "vul.timeout"
	keyVulIgnoreFile             = "vul.ignoreFile"
	keyVulInsecureRegistryPrefix = "vul.insecureRegistry."
	keyVulNonSslRegistryPrefix   = "vul.nonSslRegistry."
	keyVulMirrorPrefix           = "vul.registry.mirror."
	keyVulHTTPProxy              = "vul.httpProxy"
	keyVulHTTPSProxy             = "vul.httpsProxy"
	keyVulNoProxy                = "vul.noProxy"
	keyVulGitHubToken            = "vul.githubToken"
	keyVulSkipFiles              = "vul.skipFiles"
	keyVulSkipDirs               = "vul.skipDirs"
	keyVulDBRepository           = "vul.dbRepository"

	keyVulServerURL           = "vul.serverURL"
	keyVulServerTokenHeader   = "vul.serverTokenHeader"
	keyVulServerInsecure      = "vul.serverInsecure"
	keyVulServerToken         = "vul.serverToken"
	keyVulServerCustomHeaders = "vul.serverCustomHeaders"

	keyResourcesRequestsCPU    = "vul.resources.requests.cpu"
	keyResourcesRequestsMemory = "vul.resources.requests.memory"
	keyResourcesLimitsCPU      = "vul.resources.limits.cpu"
	keyResourcesLimitsMemory   = "vul.resources.limits.memory"
)

const defaultDBRepository = "ghcr.io/khulnasoft-lab/vul-db"

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
)

// Config defines configuration params for this plugin.
type Config struct {
	starboard.PluginConfig
}

// GetImageRef returns upstream Vul container image reference.
func (c Config) GetImageRef() (string, error) {
	return c.GetRequiredData(keyVulImageRef)
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
	}
	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s)",
		value, keyVulCommand, Image, Filesystem)
}

func (c Config) GetServerURL() (string, error) {
	return c.GetRequiredData(keyVulServerURL)
}

func (c Config) GetServerInsecure() bool {
	_, ok := c.Data[keyVulServerInsecure]
	return ok
}

func (c Config) IgnoreFileExists() bool {
	_, ok := c.Data[keyVulIgnoreFile]
	return ok
}

func (c Config) IgnoreUnfixed() bool {
	_, ok := c.Data[keyVulIgnoreUnfixed]
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

	err = c.setResourceLimit(keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
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

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx starboard.PluginContext) error {
	return ctx.EnsureConfig(starboard.PluginConfig{
		Data: map[string]string{
			keyVulImageRef:     "docker.io/khulnasoft/vul:0.25.2",
			keyVulSeverity:     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			keyVulMode:         string(Standalone),
			keyVulTimeout:      "5m0s",
			keyVulDBRepository: defaultDBRepository,

			keyResourcesRequestsCPU:    "100m",
			keyResourcesRequestsMemory: "100M",
			keyResourcesLimitsCPU:      "500m",
			keyResourcesLimitsMemory:   "500M",
		},
	})
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	mode, err := config.GetMode()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	command, err := config.GetCommand()

	if command == Image {
		switch mode {
		case Standalone:
			return p.getPodSpecForStandaloneMode(ctx, config, workload, credentials)
		case ClientServer:
			return p.getPodSpecForClientServerMode(ctx, config, workload, credentials)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized vul mode %q for command %q", mode, command)
		}
	}

	if command == Filesystem {
		switch mode {
		case Standalone:
			return p.getPodSpecForStandaloneFSMode(ctx, config, workload)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized vul mode %q for command %q", mode, command)
		}
	}

	return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized vul command %q", command)
}

func (p *plugin) newSecretWithAggregateImagePullCredentials(obj client.Object, spec corev1.PodSpec, credentials map[string]docker.Auth) *corev1.Secret {
	containerImages := kube.GetContainerImagesFromPodSpec(spec)
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: vulnerabilityreport.RegistryCredentialsSecretName(obj),
		},
		Data: secretData,
	}
}

const (
	tmpVolumeName             = "tmp"
	ignoreFileVolumeName      = "ignorefile"
	FsSharedVolumeName        = "starboard"
	SharedVolumeLocationOfVul = "/var/starboard/vul"
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
func (p *plugin) getPodSpecForStandaloneMode(ctx starboard.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	if len(credentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, spec, credentials)
		secrets = append(secrets, secret)
	}

	vulImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	vulConfigName := starboard.GetPluginConfigMapName(Plugin)

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
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env: []corev1.EnvVar{
			{
				Name: "HTTP_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulHTTPProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulHTTPSProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulNoProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "GITHUB_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulGitHubToken,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		},
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
		Resources: requirements,
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

	if config.IgnoreFileExists() {
		volumes = append(volumes, corev1.Volume{
			Name: ignoreFileVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: vulConfigName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  keyVulIgnoreFile,
							Path: ".vulignore",
						},
					},
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      ignoreFileVolumeName,
			MountPath: "/etc/vul/.vulignore",
			SubPath:   ".vulignore",
		})
	}

	for _, c := range spec.Containers {

		env := []corev1.EnvVar{
			{
				Name: "VUL_SEVERITY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulSeverity,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_IGNORE_UNFIXED",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulIgnoreUnfixed,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_TIMEOUT",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulTimeout,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_SKIP_FILES",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulSkipFiles,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_SKIP_DIRS",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulSkipDirs,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTP_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulHTTPProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulHTTPSProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulNoProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		}

		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNOREFILE",
				Value: "/etc/vul/.vulignore",
			})
		}

		region := CheckAwsEcrPrivateRegistry(c.Image)
		if region != "" {
			env = append(env, corev1.EnvVar{
				Name:  "AWS_REGION",
				Value: region,
			})
		}

		if _, ok := credentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)

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

		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    vulImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				"vul",
			},
			Args: []string{
				"--cache-dir",
				"/tmp/vul/.cache",
				"--quiet",
				"image",
				"--skip-update",
				"--format",
				"json",
				optionalMirroredImage,
			},
			Resources:    resourceRequirements,
			VolumeMounts: volumeMounts,
			SecurityContext: &corev1.SecurityContext{
				Privileged:               pointer.BoolPtr(false),
				AllowPrivilegeEscalation: pointer.BoolPtr(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: pointer.BoolPtr(true),
			},
		})
	}

	return corev1.PodSpec{
		Affinity:                     starboard.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainer},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

// In the ClientServer mode the number of containers of the pod created by the
// scan job equals the number of containers defined for the scanned workload.
// Each container runs Vul image scan command and refers to Vul server URL
// returned by Config.GetServerURL:
//
//	vul client --remote <server URL> \
//	  --format json <container image>
func (p *plugin) getPodSpecForClientServerMode(ctx starboard.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var volumeMounts []corev1.VolumeMount
	var volumes []corev1.Volume

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

	if len(credentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, spec, credentials)
		secrets = append(secrets, secret)
	}

	var containers []corev1.Container

	vulConfigName := starboard.GetPluginConfigMapName(Plugin)

	for _, container := range spec.Containers {

		env := []corev1.EnvVar{
			{
				Name: "HTTP_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulHTTPProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulHTTPSProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulNoProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_SEVERITY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulSeverity,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_IGNORE_UNFIXED",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulIgnoreUnfixed,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_TIMEOUT",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulTimeout,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_SKIP_FILES",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulSkipFiles,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_SKIP_DIRS",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulSkipDirs,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_TOKEN_HEADER",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulServerTokenHeader,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulServerToken,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "VUL_CUSTOM_HEADERS",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulServerCustomHeaders,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		}

		if _, ok := credentials[container.Name]; ok && secret != nil {
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

		if config.IgnoreFileExists() {
			volumes = []corev1.Volume{
				{
					Name: ignoreFileVolumeName,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: vulConfigName,
							},
							Items: []corev1.KeyToPath{
								{
									Key:  keyVulIgnoreFile,
									Path: ".vulignore",
								},
							},
						},
					},
				},
			}

			volumeMounts = []corev1.VolumeMount{
				{
					Name:      ignoreFileVolumeName,
					MountPath: "/etc/vul/.vulignore",
					SubPath:   ".vulignore",
				},
			}

			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNOREFILE",
				Value: "/etc/vul/.vulignore",
			})
		}

		requirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		optionalMirroredImage, err := GetMirroredImage(container.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		containers = append(containers, corev1.Container{
			Name:                     container.Name,
			Image:                    vulImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				"vul",
			},
			Args: []string{
				"--quiet",
				"client",
				"--format",
				"json",
				"--remote",
				vulServerURL,
				optionalMirroredImage,
			},
			VolumeMounts: volumeMounts,
			Resources:    requirements,
		})
	}

	return corev1.PodSpec{
		Affinity:                     starboard.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Containers:                   containers,
		Volumes:                      volumes,
	}, secrets, nil
}

// FileSystem scan option with standalone mode.
// The only difference is that instead of scanning the resource by name,
// We scanning the resource place on a specific file system location using the following command.
//
//	vul --quiet fs  --format json --ignore-unfixed  file/system/location
func (p *plugin) getPodSpecForStandaloneFSMode(ctx starboard.PluginContext, config Config,
	workload client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	var secrets []*corev1.Secret
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	pullPolicy := corev1.PullIfNotPresent
	// nodeName to schedule scan job explicitly on specific node.
	var nodeName string
	if !ctx.GetStarboardConfig().VulnerabilityScanJobsInSameNamespace() {
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

	vulConfigName := starboard.GetPluginConfigMapName(Plugin)

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
			MountPath: "/var/starboard",
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    vulImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/vul",
			SharedVolumeLocationOfVul,
		},
		Resources:    requirements,
		VolumeMounts: volumeMounts,
	}

	initContainerDB := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    vulImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env: []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
			{
				Name: "GITHUB_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vulConfigName,
						},
						Key:      keyVulGitHubToken,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		},
		Command: []string{
			"vul",
		},
		Args: []string{
			"--download-db-only",
			"--cache-dir",
			"/var/starboard/vul-db",
			"--db-repository",
			dbRepository,
		},
		Resources:    requirements,
		VolumeMounts: volumeMounts,
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
	}

	//TODO Move this to function and refactor the code to use it
	if config.IgnoreFileExists() {
		volumes = append(volumes, corev1.Volume{
			Name: ignoreFileVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: vulConfigName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  keyVulIgnoreFile,
							Path: ".vulignore",
						},
					},
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      ignoreFileVolumeName,
			MountPath: "/tmp/vul/.vulignore",
			SubPath:   ".vulignore",
		})
	}

	for _, c := range spec.Containers {

		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("VUL_SEVERITY", vulConfigName, keyVulSeverity),
			constructEnvVarSourceFromConfigMap("VUL_SKIP_FILES", vulConfigName, keyVulSkipFiles),
			constructEnvVarSourceFromConfigMap("VUL_SKIP_DIRS", vulConfigName, keyVulSkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", vulConfigName, keyVulHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", vulConfigName, keyVulHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", vulConfigName, keyVulNoProxy),
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "VUL_IGNOREFILE",
				Value: "/tmp/vul/.vulignore",
			})
		}
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("VUL_IGNORE_UNFIXED",
				vulConfigName, keyVulIgnoreUnfixed))
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
			Args: []string{
				"--skip-update",
				"--cache-dir",
				"/var/starboard/vul-db",
				"--quiet",
				"fs",
				"--format",
				"json",
				"/",
			},
			Resources:    resourceRequirements,
			VolumeMounts: volumeMounts,
			// Todo review security Context which is better for vul fs scan
			SecurityContext: &corev1.SecurityContext{
				Privileged:               pointer.BoolPtr(false),
				AllowPrivilegeEscalation: pointer.BoolPtr(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				// Currently Vul needs to run as root user to scan filesystem, So we will run fs scan job with root user.
				RunAsUser: pointer.Int64(0),
			},
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     starboard.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainerCopyBinary, initContainerDB},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}

	if !ctx.GetStarboardConfig().VulnerabilityScanJobsInSameNamespace() {
		// schedule scan job explicitly on specific node.
		podSpec.NodeName = nodeName
	}

	return podSpec, secrets, nil
}

func (p *plugin) appendVulInsecureEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := name.ParseReference(image)
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
	ref, err := name.ParseReference(image)
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

func (p *plugin) ParseVulnerabilityReportData(ctx starboard.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}
	var reports ScanReport
	err = json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, report := range reports.Results {
		for _, sr := range report.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, v1alpha1.Vulnerability{
				VulnerabilityID:  sr.VulnerabilityID,
				Resource:         sr.PkgName,
				InstalledVersion: sr.InstalledVersion,
				FixedVersion:     sr.FixedVersion,
				Severity:         sr.Severity,
				Title:            sr.Title,
				PrimaryLink:      sr.PrimaryURL,
				Links:            []string{},
				Score:            GetScoreFromCVSS(sr.Cvss),
			})
		}
	}

	registry, artifact, err := p.parseImageRef(imageRef)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	vulImageRef, err := config.GetImageRef()
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	version, err := starboard.GetVersionFromImageRef(vulImageRef)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	return v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Vul",
			Vendor:  "KhulnaSoft",
			Version: version,
		},
		Registry:        registry,
		Artifact:        artifact,
		Summary:         p.toSummary(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (p *plugin) newConfigFrom(ctx starboard.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

func (p *plugin) toSummary(vulnerabilities []v1alpha1.Vulnerability) v1alpha1.VulnerabilitySummary {
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

func (p *plugin) parseImageRef(imageRef string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
	ref, err := name.ParseReference(imageRef)
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
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}
	return registry, artifact, nil
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

	if vendorScore != nil {
		return vendorScore
	}

	return nvdScore
}

func GetMirroredImage(image string, mirrors map[string]string) (string, error) {
	ref, err := name.ParseReference(image)
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
				Optional: pointer.BoolPtr(true),
			},
		},
	}
	return
}

func CheckAwsEcrPrivateRegistry(ImageUrl string) string {
	if len(regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)) != 0 {
		return regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)[0][1]
	}
	return ""
}
