package sbomreport_test

import (
	"context"
	"testing"

	"github.com/khulnasoft-lab/vul-operator/pkg/apis/khulnasoft-lab/v1alpha1"
	"github.com/khulnasoft-lab/vul-operator/pkg/kube"
	"github.com/khulnasoft-lab/vul-operator/pkg/sbomreport"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewReadWriter(t *testing.T) {

	kubernetesScheme := vuloperator.NewScheme()

	t.Run("Should create SbomReports", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := sbomreport.NewReadWriter(&resolver)
		err := readWriter.Write(context.TODO(), []v1alpha1.SbomReport{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deployment-app1-container1",
					Namespace: "qa",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container1",
						vuloperator.LabelResourceSpecHash:  "h1",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deployment-app1-container2",
					Namespace: "qa",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container2",
						vuloperator.LabelResourceSpecHash:  "h1",
					},
				},
			},
		})
		require.NoError(t, err)
		var list v1alpha1.SbomReportList
		err = testClient.List(context.TODO(), &list)
		require.NoError(t, err)
		reports := map[string]v1alpha1.SbomReport{}
		for _, item := range list.Items {
			reports[item.Name] = item
		}
		assert.Equal(t, map[string]v1alpha1.SbomReport{
			"deployment-app1-container1": {
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "qa",
					Name:      "deployment-app1-container1",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container1",
						vuloperator.LabelResourceSpecHash:  "h1",
					},
					ResourceVersion: "1",
				},
			},
			"deployment-app1-container2": {
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "qa",
					Name:      "deployment-app1-container2",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container2",
						vuloperator.LabelResourceSpecHash:  "h1",
					},
					ResourceVersion: "1",
				},
			},
		}, reports)
	})

	t.Run("Should update SbomReports", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.SbomReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "deployment-app1-container1",
					Namespace:       "qa",
					ResourceVersion: "0",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container1",
						vuloperator.LabelResourceSpecHash:  "h1",
					},
				},
			},
			&v1alpha1.SbomReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "deployment-app1-container2",
					Namespace:       "qa",
					ResourceVersion: "0",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container2",
						vuloperator.LabelResourceSpecHash:  "h2",
					},
				},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := sbomreport.NewReadWriter(&resolver)
		err := readWriter.Write(context.TODO(), []v1alpha1.SbomReport{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deployment-app1-container1",
					Namespace: "qa",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container1",
						vuloperator.LabelResourceSpecHash:  "h2",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deployment-app1-container2",
					Namespace: "qa",
					Labels: map[string]string{
						vuloperator.LabelResourceKind:      "Deployment",
						vuloperator.LabelResourceName:      "app1",
						vuloperator.LabelResourceNamespace: "qa",
						vuloperator.LabelContainerName:     "container2",
						vuloperator.LabelResourceSpecHash:  "h2",
					},
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.SbomReport
		err = testClient.Get(context.TODO(), types.NamespacedName{
			Namespace: "qa",
			Name:      "deployment-app1-container1",
		}, &found)
		require.NoError(t, err)
		assert.Equal(t, v1alpha1.SbomReport{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "khulnasoft-lab.github.io/v1alpha1",
				Kind:       "SbomReport",
			},
			ObjectMeta: metav1.ObjectMeta{
				ResourceVersion: "1",
				Name:            "deployment-app1-container1",
				Namespace:       "qa",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Deployment",
					vuloperator.LabelResourceName:      "app1",
					vuloperator.LabelResourceNamespace: "qa",
					vuloperator.LabelContainerName:     "container1",
					vuloperator.LabelResourceSpecHash:  "h2",
				},
			},
		}, found)

		err = testClient.Get(context.TODO(), types.NamespacedName{
			Namespace: "qa",
			Name:      "deployment-app1-container2",
		}, &found)
		require.NoError(t, err)
		assert.Equal(t, v1alpha1.SbomReport{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "khulnasoft-lab.github.io/v1alpha1",
				Kind:       "SbomReport",
			},
			ObjectMeta: metav1.ObjectMeta{
				ResourceVersion: "1",
				Name:            "deployment-app1-container2",
				Namespace:       "qa",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "Deployment",
					vuloperator.LabelResourceName:      "app1",
					vuloperator.LabelResourceNamespace: "qa",
					vuloperator.LabelContainerName:     "container2",
					vuloperator.LabelResourceSpecHash:  "h2",
				},
			},
		}, found)
	})

	t.Run("Should find SbomReports", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1alpha1.SbomReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "my-namespace",
				Name:      "deployment-my-deploy-my-container-01",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      string(kube.KindDeployment),
					vuloperator.LabelResourceName:      "my-deploy",
					vuloperator.LabelResourceNamespace: "my-namespace",
					vuloperator.LabelContainerName:     "my-container-01",
				},
			},
			Report: v1alpha1.SbomReportData{},
		}, &v1alpha1.SbomReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "my-namespace",
				Name:      "deployment-my-deploy-my-container-02",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      string(kube.KindDeployment),
					vuloperator.LabelResourceName:      "my-deploy",
					vuloperator.LabelResourceNamespace: "my-namespace",
					vuloperator.LabelContainerName:     "my-container-02",
				},
			},
			Report: v1alpha1.SbomReportData{},
		}, &v1alpha1.SbomReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "my-namespace",
				Name:      "my-sts",
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      string(kube.KindStatefulSet),
					vuloperator.LabelResourceName:      "my-sts",
					vuloperator.LabelResourceNamespace: "my-namespace",
					vuloperator.LabelContainerName:     "my-sts-container",
				},
			},
			Report: v1alpha1.SbomReportData{},
		}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := sbomreport.NewReadWriter(&resolver)
		list, err := readWriter.FindByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindDeployment,
			Name:      "my-deploy",
			Namespace: "my-namespace",
		})
		require.NoError(t, err)
		reports := map[string]bool{}
		for _, item := range list {
			reports[item.Name] = true
		}
		assert.Equal(t, map[string]bool{
			"deployment-my-deploy-my-container-01": true,
			"deployment-my-deploy-my-container-02": true,
		}, reports)
	})
}
