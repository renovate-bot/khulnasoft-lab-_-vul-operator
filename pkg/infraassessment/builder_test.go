package infraassessment_test

import (
	"testing"

	"github.com/khulnasoft-lab/vul-operator/pkg/apis/khulnasoft-lab/v1alpha1"
	"github.com/khulnasoft-lab/vul-operator/pkg/infraassessment"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
)

func TestReportBuilder(t *testing.T) {

	t.Run("Should build report for namespaced resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := infraassessment.NewReportBuilder(scheme.Scheme).
			Controller(&appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-owner",
					Namespace: "qa",
					Labels:    labels.Set{"tier": "tier-1", "owner": "team-a"},
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.InfraAssessmentReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicaset-some-owner",
				Namespace: "qa",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "apps/v1",
						Kind:               "ReplicaSet",
						Name:               "some-owner",
						Controller:         pointer.Bool(true),
						BlockOwnerDeletion: pointer.Bool(false),
					},
				},
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "ReplicaSet",
					vuloperator.LabelResourceName:      "some-owner",
					vuloperator.LabelResourceNamespace: "qa",
					vuloperator.LabelResourceSpecHash:  "xyz",
					vuloperator.LabelPluginConfigHash:  "nop",
					"tier":                               "tier-1",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}))
	})
}
