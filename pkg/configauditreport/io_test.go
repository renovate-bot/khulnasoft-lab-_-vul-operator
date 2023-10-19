package configauditreport_test

import (
	"context"
	"testing"

	v1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"

	"github.com/khulnasoft-lab/vul-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft-lab/vul-operator/pkg/configauditreport"
	"github.com/khulnasoft-lab/vul-operator/pkg/kube"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReadWriter(t *testing.T) {

	kubernetesScheme := vuloperator.NewScheme()

	t.Run("Should create ConfigAuditReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := configauditreport.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Deployment",
					vuloperator.LabelResourceName:      "app",
					vuloperator.LabelResourceNamespace: "qa",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ConfigAuditReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "deployment-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigAuditReport",
				APIVersion: "khulnasoft-lab.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Deployment",
					vuloperator.LabelResourceName:      "app",
					vuloperator.LabelResourceNamespace: "qa",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update ConfigAuditReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1beta1.CronJob{}, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "deployment-app",
				Namespace:       "qa",
				ResourceVersion: "0",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Deployment",
					vuloperator.LabelResourceName:      "app",
					vuloperator.LabelResourceNamespace: "qa",
					vuloperator.LabelResourceSpecHash:  "h1",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := configauditreport.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Deployment",
					vuloperator.LabelResourceName:      "app",
					vuloperator.LabelResourceNamespace: "qa",
					vuloperator.LabelResourceSpecHash:  "h2",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ConfigAuditReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "deployment-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigAuditReport",
				APIVersion: "khulnasoft-lab.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Deployment",
					vuloperator.LabelResourceName:      "app",
					vuloperator.LabelResourceNamespace: "qa",
					vuloperator.LabelResourceSpecHash:  "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find ConfigAuditReport by owner", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1beta1.CronJob{},
			&v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "my-namespace",
					Name:            "deployment-my-deploy-my",
					ResourceVersion: "0",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      string(kube.KindDeployment),
						vuloperator.LabelResourceName:      "my-deploy",
						vuloperator.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}, &v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "my-namespace",
					Name:      "my-sts",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      string(kube.KindStatefulSet),
						vuloperator.LabelResourceName:      "my-sts",
						vuloperator.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := configauditreport.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindDeployment,
			Name:      "my-deploy",
			Namespace: "my-namespace",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "my-namespace",
				Name:            "deployment-my-deploy-my",
				ResourceVersion: "0",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      string(kube.KindDeployment),
					vuloperator.LabelResourceName:      "my-deploy",
					vuloperator.LabelResourceNamespace: "my-namespace",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}, found)
	})

	t.Run("Should find ConfigAuditReport by owner with special name", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-79f88497",
					ResourceVersion: "0",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Role",
						vuloperator.LabelResourceNameHash:  "79f88497",
						vuloperator.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						vuloperator.LabelResourceName: "system:controller:cloud-provider",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}, &v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-868458b9d6",
					ResourceVersion: "0",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Role",
						vuloperator.LabelResourceNameHash:  "868458b9d6",
						vuloperator.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						vuloperator.LabelResourceName: "system:controller:token-cleaner",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := configauditreport.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindRole,
			Name:      "system:controller:token-cleaner",
			Namespace: "kube-system",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "kube-system",
				Name:            "role-868458b9d6",
				ResourceVersion: "0",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Role",
					vuloperator.LabelResourceNameHash:  "868458b9d6",
					vuloperator.LabelResourceNamespace: "kube-system",
				},
				Annotations: map[string]string{
					vuloperator.LabelResourceName: "system:controller:token-cleaner",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}, found)
	})

	t.Run("Should create ClusterConfigAuditReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := configauditreport.NewReadWriter(&resolver)
		err := readWriter.WriteClusterReport(context.TODO(), v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					vuloperator.LabelResourceKind: "ClusterRole",
					vuloperator.LabelResourceName: "admin",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ClusterConfigAuditReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Name: "clusterrole-admin"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ClusterConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterConfigAuditReport",
				APIVersion: "khulnasoft-lab.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					vuloperator.LabelResourceKind: "ClusterRole",
					vuloperator.LabelResourceName: "admin",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update ClusterConfigAuditReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).WithObjects(&v1beta1.CronJob{},
			&v1alpha1.ClusterConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "clusterrole-admin",
					ResourceVersion: "0",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:     "ClusterRole",
						vuloperator.LabelResourceName:     "admin",
						vuloperator.LabelResourceSpecHash: "h1",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{
					Summary: v1alpha1.ConfigAuditSummary{
						LowCount:      8,
						CriticalCount: 3,
					},
				},
			}).
			Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := configauditreport.NewReadWriter(&resolver)
		err := readWriter.WriteClusterReport(context.TODO(), v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:     "ClusterRole",
					vuloperator.LabelResourceName:     "admin",
					vuloperator.LabelResourceSpecHash: "h2",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ClusterConfigAuditReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Name: "clusterrole-admin"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ClusterConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterConfigAuditReport",
				APIVersion: "khulnasoft-lab.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:     "ClusterRole",
					vuloperator.LabelResourceName:     "admin",
					vuloperator.LabelResourceSpecHash: "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find ClusterConfigAuditReport by owner", func(t *testing.T) {
		testClient := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).
			WithObjects(&v1.CronJob{},
				&v1alpha1.ClusterConfigAuditReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-viewer",
						ResourceVersion: "1",
						Labels: map[string]string{
							vuloperator.LabelResourceKind:      "ClusterRole",
							vuloperator.LabelResourceName:      "viewer",
							vuloperator.LabelResourceNamespace: "",
						},
					},
					Report: v1alpha1.ConfigAuditReportData{},
				},
				&v1alpha1.ClusterConfigAuditReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-editor",
						ResourceVersion: "1",
						Labels: map[string]string{
							vuloperator.LabelResourceKind:      "ClusterRole",
							vuloperator.LabelResourceName:      "editor",
							vuloperator.LabelResourceNamespace: "",
						},
					},
					Report: v1alpha1.ConfigAuditReportData{},
				}).
			Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := configauditreport.NewReadWriter(&resolver)
		found, err := readWriter.FindClusterReportByOwner(context.TODO(), kube.ObjectRef{
			Kind: "ClusterRole",
			Name: "editor",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "clusterrole-editor",
				ResourceVersion: "1",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "ClusterRole",
					vuloperator.LabelResourceName:      "editor",
					vuloperator.LabelResourceNamespace: "",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}, found)
	})
}
