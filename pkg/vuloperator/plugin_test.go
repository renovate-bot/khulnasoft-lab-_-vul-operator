package vuloperator_test

import (
	"testing"

	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetPluginConfigMapName(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	name := vuloperator.GetPluginConfigMapName("Vul")
	g.Expect(name).To(gomega.Equal("vul-operator-vul-config"))
}

func TestPluginContext_GetConfig(t *testing.T) {

	t.Run("Should return PluginConfig from ConfigMap", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		client := fake.NewClientBuilder().
			WithScheme(vuloperator.NewScheme()).
			WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vul-operator-vul-config",
					Namespace: "vuloperator-ns",
				},
				Data: map[string]string{
					"foo": "bar",
				},
			}).
			Build()

		pluginContext := vuloperator.NewPluginContext().
			WithName("vul").
			WithNamespace("vuloperator-ns").
			WithClient(client).
			Get()

		cm, err := pluginContext.GetConfig()

		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm).To(gomega.Equal(
			vuloperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}))
	})

	t.Run("Should return PluginConfig from ConfigMap and Secret", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		client := fake.NewClientBuilder().
			WithScheme(vuloperator.NewScheme()).
			WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vul-operator-vul-config",
					Namespace: "vuloperator-ns",
				},
				Data: map[string]string{
					"foo": "bar",
				},
			}, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vul-operator-vul-config",
					Namespace: "vuloperator-ns",
				},
				Data: map[string][]byte{
					"secret": []byte("pa$$word"),
				},
			}).
			Build()

		pluginContext := vuloperator.NewPluginContext().
			WithName("vul").
			WithNamespace("vuloperator-ns").
			WithClient(client).
			Get()

		cm, err := pluginContext.GetConfig()

		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm).To(gomega.Equal(
			vuloperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
				SecretData: map[string][]byte{
					"secret": []byte("pa$$word"),
				},
			}))
	})
}
