package configauditreport_test

import (
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/labels"

	"testing"

	"github.com/khulnasoft-lab/vul-operator/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft-lab/vul-operator/pkg/configauditreport"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
)

func TestReportBuilder(t *testing.T) {

	t.Run("Should build report for namespaced resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
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
			Data(v1alpha1.ConfigAuditReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ConfigAuditReport{
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
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})

	t.Run("Should build report for cluster scoped resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:   "system:controller:node-controller",
					Labels: labels.Set{"tier": "tier-1", "owner": "team-a"},
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetClusterReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-6f69bb5b79",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "ClusterRole",
						Name:               "system:controller:node-controller",
						Controller:         pointer.Bool(true),
						BlockOwnerDeletion: pointer.Bool(false),
					},
				},
				Labels: map[string]string{
					vuloperator.LabelResourceKind:      "ClusterRole",
					vuloperator.LabelResourceNameHash:  "6f69bb5b79",
					vuloperator.LabelResourceNamespace: "",
					vuloperator.LabelResourceSpecHash:  "xyz",
					vuloperator.LabelPluginConfigHash:  "nop",
					"tier":                               "tier-1",
				},
				Annotations: map[string]string{
					vuloperator.LabelResourceName: "system:controller:node-controller",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})

	t.Run("Should build report with lowercase name", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-Reader",
					Labels:    labels.Set{"tier": "tier-1", "owner": "team-a"},
					Namespace: "test",
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-65c67c5c64",
				Namespace: "test",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "Role",
						Name:               "pod-Reader",
						Controller:         pointer.Bool(true),
						BlockOwnerDeletion: pointer.Bool(false),
					},
				},
				Labels: map[string]string{
					vuloperator.LabelPluginConfigHash:  "nop",
					vuloperator.LabelResourceKind:      "Role",
					vuloperator.LabelResourceNamespace: "test",
					vuloperator.LabelResourceName:      "pod-Reader",
					"tier":                               "tier-1",
					vuloperator.LabelResourceSpecHash:  "xyz",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})
}
