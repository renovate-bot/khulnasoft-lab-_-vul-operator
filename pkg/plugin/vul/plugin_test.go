package vul_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/khulnasoft-lab/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft-lab/starboard/pkg/ext"
	"github.com/khulnasoft-lab/starboard/pkg/kube"
	"github.com/khulnasoft-lab/starboard/pkg/plugin/vul"
	"github.com/khulnasoft-lab/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

const defaultDBRepository = "ghcr.io/khulnasoft-lab/vul-db"

func TestConfig_GetImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       vul.Config
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    vul.Config{PluginConfig: starboard.PluginConfig{}},
			expectedError: "property vul.imageRef not set",
		},
		{
			name: "Should return image reference from config data",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.imageRef": "gcr.io/khulnasoft-lab/vul:0.8.0",
				},
			}},
			expectedImageRef: "gcr.io/khulnasoft-lab/vul:0.8.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, err := tc.configData.GetImageRef()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedImageRef, imageRef)
			}
		})
	}
}

func TestConfig_GetMode(t *testing.T) {
	testCases := []struct {
		name          string
		configData    vul.Config
		expectedError string
		expectedMode  vul.Mode
	}{
		{
			name: "Should return Standalone",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.mode": "Standalone",
				},
			}},
			expectedMode: vul.Standalone,
		},
		{
			name: "Should return ClientServer",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.mode": "ClientServer",
				},
			}},
			expectedMode: vul.ClientServer,
		},
		{
			name:          "Should return error when value is not set",
			configData:    vul.Config{PluginConfig: starboard.PluginConfig{}},
			expectedError: "property vul.mode not set",
		},
		{
			name: "Should return error when value is not allowed",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.mode": "P2P",
				},
			}},
			expectedError: "invalid value (P2P) of vul.mode; allowed values (Standalone, ClientServer)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := tc.configData.GetMode()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedMode, mode)
			}
		})
	}
}

func TestConfig_GetCommand(t *testing.T) {
	testCases := []struct {
		name            string
		configData      vul.Config
		expectedError   string
		expectedCommand vul.Command
	}{
		{
			name: "Should return image",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.command": "image",
				},
			}},
			expectedCommand: vul.Image,
		},
		{
			name: "Should return image when value is not set",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{},
			}},
			expectedCommand: vul.Image,
		},
		{
			name: "Should return filesystem",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.command": "filesystem",
				},
			}},
			expectedCommand: vul.Filesystem,
		},
		{
			name: "Should return error when value is not allowed",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.command": "ls",
				},
			}},
			expectedError: "invalid value (ls) of vul.command; allowed values (image, filesystem)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			command, err := tc.configData.GetCommand()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCommand, command)
			}
		})
	}
}

func TestConfig_GetResourceRequirements(t *testing.T) {
	testCases := []struct {
		name                 string
		config               vul.Config
		expectedError        string
		expectedRequirements corev1.ResourceRequirements
	}{
		{
			name: "Should return empty requirements by default",
			config: vul.Config{
				PluginConfig: starboard.PluginConfig{},
			},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{},
				Limits:   corev1.ResourceList{},
			},
		},
		{
			name: "Should return configured resource requirement",
			config: vul.Config{
				PluginConfig: starboard.PluginConfig{
					Data: map[string]string{
						"vul.dbRepository":              defaultDBRepository,
						"vul.resources.requests.cpu":    "800m",
						"vul.resources.requests.memory": "200M",
						"vul.resources.limits.cpu":      "600m",
						"vul.resources.limits.memory":   "700M",
					},
				},
			},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("800m"),
					corev1.ResourceMemory: resource.MustParse("200M"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("600m"),
					corev1.ResourceMemory: resource.MustParse("700M"),
				},
			},
		},
		{
			name: "Should return error if resource is not parseable",
			config: vul.Config{
				PluginConfig: starboard.PluginConfig{
					Data: map[string]string{
						"vul.resources.requests.cpu": "roughly 100",
					},
				},
			},
			expectedError: "parsing resource definition vul.resources.requests.cpu: roughly 100 quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resourceRequirement, err := tc.config.GetResourceRequirements()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRequirements, resourceRequirement, tc.name)
			}
		})
	}
}

func TestConfig_IgnoreFileExists(t *testing.T) {
	testCases := []struct {
		name           string
		configData     vul.Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
					"vul.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				},
			}},
			expectedOutput: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.IgnoreFileExists()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}

func TestConfig_IgnoreUnfixed(t *testing.T) {
	testCases := []struct {
		name           string
		configData     vul.Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo":               "bar",
					"vul.ignoreUnfixed": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "Should return false when set it as false",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo":               "bar",
					"vul.ignoreUnfixed": "false",
				},
			}},
			expectedOutput: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.IgnoreUnfixed()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}

func TestConfig_GetInsecureRegistries(t *testing.T) {
	testCases := []struct {
		name           string
		configData     vul.Config
		expectedOutput map[string]bool
	}{
		{
			name: "Should return nil map when there is no key with vul.insecureRegistry. prefix",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]bool),
		},
		{
			name: "Should return insecure registries in map",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo":                              "bar",
					"vul.insecureRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
					"vul.insecureRegistry.qaRegistry":  "qa.registry.khulnasoft.com",
				},
			}},
			expectedOutput: map[string]bool{
				"poc.myregistry.harbor.com.pl": true,
				"qa.registry.khulnasoft.com":   true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			insecureRegistries := tc.configData.GetInsecureRegistries()
			assert.Equal(t, tc.expectedOutput, insecureRegistries)
		})
	}
}

func TestConfig_GetNonSSLRegistries(t *testing.T) {
	testCases := []struct {
		name           string
		configData     vul.Config
		expectedOutput map[string]bool
	}{
		{
			name: "Should return nil map when there is no key with vul.nonSslRegistry. prefix",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]bool),
		},
		{
			name: "Should return insecure registries in map",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo":                            "bar",
					"vul.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
					"vul.nonSslRegistry.qaRegistry":  "qa.registry.khulnasoft.com",
				},
			}},
			expectedOutput: map[string]bool{
				"poc.myregistry.harbor.com.pl": true,
				"qa.registry.khulnasoft.com":   true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nonSslRegistries := tc.configData.GetNonSSLRegistries()
			assert.Equal(t, tc.expectedOutput, nonSslRegistries)
		})
	}
}

func TestConfig_GetMirrors(t *testing.T) {
	testCases := []struct {
		name           string
		configData     vul.Config
		expectedOutput map[string]string
	}{
		{
			name: "Should return empty map when there is no key with vul.mirrors.registry. prefix",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]string),
		},
		{
			name: "Should return mirrors in a map",
			configData: vul.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"vul.registry.mirror.docker.io": "mirror.io",
				},
			}},
			expectedOutput: map[string]string{"docker.io": "mirror.io"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedOutput, tc.configData.GetMirrors())
		})
	}
}

func TestPlugin_Init(t *testing.T) {

	t.Run("Should create the default config", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithObjects().Build()
		objectResolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		instance := vul.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &objectResolver)

		pluginContext := starboard.NewPluginContext().
			WithName(vul.Plugin).
			WithNamespace("starboard-ns").
			WithServiceAccountName("starboard-sa").
			WithClient(testClient).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

		var cm corev1.ConfigMap
		err = testClient.Get(context.Background(), types.NamespacedName{
			Namespace: "starboard-ns",
			Name:      "starboard-vul-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "starboard-vul-config",
				Namespace: "starboard-ns",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "starboard",
				},
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"vul.imageRef":     "docker.io/khulnasoft/vul:0.25.2",
				"vul.severity":     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"vul.mode":         "Standalone",
				"vul.timeout":      "5m0s",
				"vul.dbRepository": defaultDBRepository,

				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
		}, cm)
	})

	t.Run("Should not overwrite existing config", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithObjects(
			&corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "starboard-vul-config",
					Namespace:       "starboard-ns",
					ResourceVersion: "1",
				},
				Data: map[string]string{
					"vul.imageRef": "docker.io/khulnasoft/vul:0.25.2",
					"vul.severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					"vul.mode":     "Standalone",
				},
			}).Build()
		objectResolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		instance := vul.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &objectResolver)

		pluginContext := starboard.NewPluginContext().
			WithName(vul.Plugin).
			WithNamespace("starboard-ns").
			WithServiceAccountName("starboard-sa").
			WithClient(testClient).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

		var cm corev1.ConfigMap
		err = testClient.Get(context.Background(), types.NamespacedName{
			Namespace: "starboard-ns",
			Name:      "starboard-vul-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "starboard-vul-config",
				Namespace:       "starboard-ns",
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"vul.imageRef": "docker.io/khulnasoft/vul:0.25.2",
				"vul.severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"vul.mode":     "Standalone",
			},
		}, cm)
	})
}

func TestPlugin_GetScanJobSpec(t *testing.T) {

	tmpVolume := corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}

	tmpVolumeMount := corev1.VolumeMount{
		Name:      "tmp",
		MountPath: "/tmp",
		ReadOnly:  false,
	}

	timeoutEnv := corev1.EnvVar{
		Name: "VUL_TIMEOUT",
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "starboard-vul-config",
				},
				Key:      "vul.timeout",
				Optional: pointer.BoolPtr(true),
			},
		},
	}

	testCases := []struct {
		name string

		config       map[string]string
		workloadSpec client.Object

		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "Standalone mode without insecure registry",
			config: map[string]string{
				"vul.imageRef":                  "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":                      string(vul.Standalone),
				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-6799fc88d8",
					Namespace: "prod-ns",
				},
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with insecure registry",
			config: map[string]string{
				"vul.imageRef":                     "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":                         string(vul.Standalone),
				"vul.insecureRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"vul.dbRepository":                 defaultDBRepository,

				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "VUL_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with non-SSL registry",
			config: map[string]string{
				"vul.imageRef":                   "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":                       string(vul.Standalone),
				"vul.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"vul.dbRepository":               defaultDBRepository,
				"vul.resources.requests.cpu":     "100m",
				"vul.resources.requests.memory":  "100M",
				"vul.resources.limits.cpu":       "500m",
				"vul.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "VUL_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with vulignore file",
			config: map[string]string{
				"vul.imageRef": "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":     string(vul.Standalone),
				"vul.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "starboard-vul-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "vul.ignoreFile",
										Path: ".vulignore",
									},
								},
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "VUL_IGNOREFILE",
								Value: "/etc/vul/.vulignore",
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
							{
								Name:      "ignorefile",
								MountPath: "/etc/vul/.vulignore",
								SubPath:   ".vulignore",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with mirror",
			config: map[string]string{
				"vul.imageRef": "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":     string(vul.Standalone),

				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",

				"vul.registry.mirror.index.docker.io": "mirror.io",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--cache-dir", "/tmp/vul/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"mirror.io/library/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "ClientServer mode without insecure registry",
			config: map[string]string{
				"vul.imageRef":                  "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":                      string(vul.ClientServer),
				"vul.serverURL":                 "http://vul.vul:4954",
				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://vul.vul:4954",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode without insecure registry",
			config: map[string]string{
				"vul.imageRef":                  "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":                      string(vul.ClientServer),
				"vul.serverURL":                 "http://vul.vul:4954",
				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://vul.vul:4954",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with insecure server",
			config: map[string]string{
				"vul.imageRef":                  "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":                      string(vul.ClientServer),
				"vul.serverURL":                 "https://vul.vul:4954",
				"vul.serverInsecure":            "true",
				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "VUL_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"https://vul.vul:4954",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with non-SSL registry",
			config: map[string]string{
				"vul.imageRef":                   "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":                       string(vul.ClientServer),
				"vul.serverURL":                  "http://vul.vul:4954",
				"vul.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"vul.dbRepository":               defaultDBRepository,
				"vul.resources.requests.cpu":     "100m",
				"vul.resources.requests.memory":  "100M",
				"vul.resources.limits.cpu":       "500m",
				"vul.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "VUL_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://vul.vul:4954",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with vulignore file",
			config: map[string]string{
				"vul.imageRef":  "docker.io/khulnasoft/vul:0.14.0",
				"vul.mode":      string(vul.ClientServer),
				"vul.serverURL": "http://vul.vul:4954",
				"vul.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "starboard-vul-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "vul.ignoreFile",
										Path: ".vulignore",
									},
								},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/khulnasoft/vul:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "VUL_IGNOREFILE",
								Value: "/etc/vul/.vulignore",
							},
						},
						Command: []string{
							"vul",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://vul.vul:4954",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "ignorefile",
								MountPath: "/etc/vul/.vulignore",
								SubPath:   ".vulignore",
							},
						},
					},
				},
			},
		},
		{
			name: "Vul fs scan command in Standalone mode",
			config: map[string]string{
				"vul.imageRef":                  "docker.io/khulnasoft/vul:0.25.2",
				"vul.mode":                      string(vul.Standalone),
				"vul.command":                   string(vul.Filesystem),
				"vul.dbRepository":              defaultDBRepository,
				"vul.resources.requests.cpu":    "100m",
				"vul.resources.requests.memory": "100M",
				"vul.resources.limits.cpu":      "500m",
				"vul.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.9.1",
						},
					},
					NodeName: "kind-control-pane",
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					{
						Name: vul.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/khulnasoft/vul:0.25.2",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Command: []string{
							"cp",
							"-v",
							"/usr/local/bin/vul",
							vul.SharedVolumeLocationOfVul,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      vul.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/starboard",
							},
						},
					},
					{
						Name:                     "00000000-0000-0000-0000-000000000002",
						Image:                    "docker.io/khulnasoft/vul:0.25.2",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.githubToken",
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
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      vul.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/starboard",
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "nginx:1.9.1",
						ImagePullPolicy:          corev1.PullNever,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "VUL_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "VUL_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-vul-config",
										},
										Key:      "vul.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							vul.SharedVolumeLocationOfVul,
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
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      vul.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/starboard",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
							RunAsUser:              pointer.Int64(0),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "starboard-vul-config",
						Namespace: "starboard-ns",
					},
					Data: tc.config,
				},
			).Build()
			pluginContext := starboard.NewPluginContext().
				WithName(vul.Plugin).
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				WithClient(fakeclient).
				Get()
			objectResolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := vul.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &objectResolver)
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}

	testCases = []struct {
		name            string
		config          map[string]string
		workloadSpec    client.Object
		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{{
		name: "Vul fs scan command in Standalone mode",
		config: map[string]string{
			"vul.imageRef":                  "docker.io/khulnasoft/vul:0.22.0",
			"vul.mode":                      string(vul.Standalone),
			"vul.command":                   string(vul.Filesystem),
			"vul.dbRepository":              defaultDBRepository,
			"vul.resources.requests.cpu":    "100m",
			"vul.resources.requests.memory": "100M",
			"vul.resources.limits.cpu":      "500m",
			"vul.resources.limits.memory":   "500M",
		},
		workloadSpec: &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: "prod-ns",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.9.1",
					},
				},
				NodeName:           "kind-control-pane",
				ServiceAccountName: "nginx-sa",
			}},
		expectedJobSpec: corev1.PodSpec{
			Affinity:                     starboard.LinuxNodeAffinity(),
			RestartPolicy:                corev1.RestartPolicyNever,
			ServiceAccountName:           "starboard-sa",
			AutomountServiceAccountToken: pointer.BoolPtr(false),
			Volumes: []corev1.Volume{
				{
					Name: vul.FsSharedVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumDefault,
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name:                     "00000000-0000-0000-0000-000000000001",
					Image:                    "docker.io/khulnasoft/vul:0.22.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Command: []string{
						"cp",
						"-v",
						"/usr/local/bin/vul",
						vul.SharedVolumeLocationOfVul,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      vul.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/starboard",
						},
					},
				},
				{
					Name:                     "00000000-0000-0000-0000-000000000002",
					Image:                    "docker.io/khulnasoft/vul:0.22.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.httpProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.httpsProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.noProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},

						{
							Name: "GITHUB_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.githubToken",
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
						"--db-repository", defaultDBRepository,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      vul.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/starboard",
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:                     "nginx",
					Image:                    "nginx:1.9.1",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "VUL_SEVERITY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.severity",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "VUL_SKIP_FILES",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.skipFiles",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "VUL_SKIP_DIRS",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.skipDirs",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.httpProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.httpsProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-vul-config",
									},
									Key:      "vul.noProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
					},
					Command: []string{
						vul.SharedVolumeLocationOfVul,
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
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      vul.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/starboard",
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.BoolPtr(false),
						AllowPrivilegeEscalation: pointer.BoolPtr(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						RunAsUser:              pointer.Int64(0),
					},
				},
			},
			SecurityContext: &corev1.PodSecurityContext{},
		},
	}}
	// Test cases when starboard is enabled with option to run job in the namespace of workload
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "starboard-vul-config",
						Namespace: "starboard-ns",
					},
					Data: tc.config,
				},
			).Build()
			pluginContext := starboard.NewPluginContext().
				WithName(vul.Plugin).
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				WithClient(fakeclient).
				WithStarboardConfig(map[string]string{starboard.KeyVulnerabilityScansInSameNamespace: "true"}).
				Get()
			objectResolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := vul.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &objectResolver)
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}
}

var (
	sampleReportAsString = `{
		"SchemaVersion": 2,
		"Results":[{
		"Target": "alpine:3.10.2 (alpine 3.10.2)",
		"Type": "alpine",
		"Vulnerabilities": [
			{
				"VulnerabilityID": "CVE-2019-1549",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1c-r0",
				"FixedVersion": "1.1.1d-r0",
				"Title": "openssl: information disclosure in fork()",
				"Description": "Usually this long long description of CVE-2019-1549",
				"Severity": "MEDIUM",
				"PrimaryURL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
				"References": [
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549"
				]
			},
			{
				"VulnerabilityID": "CVE-2019-1547",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1c-r0",
				"FixedVersion": "1.1.1d-r0",
				"Title": "openssl: side-channel weak encryption vulnerability",
				"Severity": "LOW",
				"PrimaryURL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				"References": [
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547"
				]
			}
		]
	}]}`

	sampleReport = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    "Vul",
			Vendor:  "KhulnaSoft",
			Version: "0.9.1",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: v1alpha1.VulnerabilitySummary{
			CriticalCount: 0,
			MediumCount:   1,
			LowCount:      1,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []v1alpha1.Vulnerability{
			{
				VulnerabilityID:  "CVE-2019-1549",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityMedium,
				Title:            "openssl: information disclosure in fork()",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
				Links:            []string{},
			},
			{
				VulnerabilityID:  "CVE-2019-1547",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityLow,
				Title:            "openssl: side-channel weak encryption vulnerability",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				Links:            []string{},
			},
		},
	}
)

func TestPlugin_ParseVulnerabilityReportData(t *testing.T) {
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "starboard-vul-config",
			Namespace: "starboard-ns",
		},
		Data: map[string]string{
			"vul.imageRef": "khulnasoft/vul:0.9.1",
		},
	}

	testCases := []struct {
		name           string
		imageRef       string
		input          string
		expectedError  error
		expectedReport v1alpha1.VulnerabilityReportData
	}{
		{
			name:           "Should convert vulnerability report in JSON format when input is quiet",
			imageRef:       "alpine:3.10.2",
			input:          sampleReportAsString,
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name:          "Should convert vulnerability report in JSON format when OS is not detected",
			imageRef:      "core.harbor.domain/library/nginx@sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
			input:         `null`,
			expectedError: nil,
			expectedReport: v1alpha1.VulnerabilityReportData{
				UpdateTimestamp: metav1.NewTime(fixedTime),
				Scanner: v1alpha1.Scanner{
					Name:    "Vul",
					Vendor:  "KhulnaSoft",
					Version: "0.9.1",
				},
				Registry: v1alpha1.Registry{
					Server: "core.harbor.domain",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "library/nginx",
					Digest:     "sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
				},
				Summary: v1alpha1.VulnerabilitySummary{
					CriticalCount: 0,
					HighCount:     0,
					MediumCount:   0,
					LowCount:      0,
					NoneCount:     0,
					UnknownCount:  0,
				},
				Vulnerabilities: []v1alpha1.Vulnerability{},
			},
		},
		{
			name:          "Should return error when image reference cannot be parsed",
			imageRef:      ":",
			input:         "null",
			expectedError: errors.New("could not parse reference: :"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithObjects(config).Build()
			ctx := starboard.NewPluginContext().
				WithName("Vul").
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				WithClient(fakeClient).
				Get()
			objectResolver := kube.NewObjectResolver(fakeClient, &kube.CompatibleObjectMapper{})
			instance := vul.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &objectResolver)
			report, err := instance.ParseVulnerabilityReportData(ctx, tc.imageRef, io.NopCloser(strings.NewReader(tc.input)))
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReport, report)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}

}

func TestGetScoreFromCVSS(t *testing.T) {
	testCases := []struct {
		name          string
		cvss          map[string]*vul.CVSS
		expectedScore *float64
	}{
		{
			name: "Should return vendor score when vendor v3 score exist",
			cvss: map[string]*vul.CVSS{
				"nvd": {
					V3Score: pointer.Float64Ptr(8.1),
				},
				"redhat": {
					V3Score: pointer.Float64Ptr(8.3),
				},
			},
			expectedScore: pointer.Float64Ptr(8.3),
		},
		{
			name: "Should return nvd score when vendor v3 score is nil",
			cvss: map[string]*vul.CVSS{
				"nvd": {
					V3Score: pointer.Float64Ptr(8.1),
				},
				"redhat": {
					V3Score: nil,
				},
			},
			expectedScore: pointer.Float64Ptr(8.1),
		},
		{
			name: "Should return nvd score when vendor doesn't exist",
			cvss: map[string]*vul.CVSS{
				"nvd": {
					V3Score: pointer.Float64Ptr(8.1),
				},
			},
			expectedScore: pointer.Float64Ptr(8.1),
		},
		{
			name: "Should return nil when vendor and nvd both v3 scores are nil",
			cvss: map[string]*vul.CVSS{
				"nvd": {
					V3Score: nil,
				},
				"redhat": {
					V3Score: nil,
				},
			},
			expectedScore: nil,
		},
		{
			name:          "Should return nil when cvss doesn't exist",
			cvss:          map[string]*vul.CVSS{},
			expectedScore: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := vul.GetScoreFromCVSS(tc.cvss)
			assert.Equal(t, tc.expectedScore, score)
		})
	}
}

func TestGetMirroredImage(t *testing.T) {
	testCases := []struct {
		name          string
		image         string
		mirrors       map[string]string
		expected      string
		expectedError string
	}{
		{
			name:     "Mirror not match",
			image:    "alpine",
			mirrors:  map[string]string{"gcr.io": "mirror.io"},
			expected: "alpine",
		},
		{
			name:     "Mirror match",
			image:    "alpine",
			mirrors:  map[string]string{"index.docker.io": "mirror.io"},
			expected: "mirror.io/library/alpine:latest",
		},
		{
			name:          "Broken image",
			image:         "alpine@sha256:broken",
			expectedError: "could not parse reference: alpine@sha256:broken",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := vul.GetMirroredImage(tc.image, tc.mirrors)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, expected)
			}
		})
	}
}
