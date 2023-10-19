package jobs_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"context"

	"github.com/khulnasoft-lab/vul-operator/pkg/operator/etc"
	"github.com/khulnasoft-lab/vul-operator/pkg/operator/jobs"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("LimitChecker", func() {

	config := etc.Config{
		Namespace:                    "vul-operator",
		ConcurrentScanJobsLimit:      2,
		ConcurrentNodeCollectorLimit: 1,
	}
	defaultVulOperatorConfig := vuloperator.GetDefaultConfig()

	Context("When there are more jobs than limit", func() {

		It("Should return true", func() {

			client := fake.NewClientBuilder().WithScheme(vuloperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "vul-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash1",
					Namespace: "vul-operator",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
						vuloperator.LabelVulnerabilityReportScanner: "Vul",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash2",
					Namespace: "vul-operator",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
						vuloperator.LabelVulnerabilityReportScanner: "Vul",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-configauditreport-hash2",
					Namespace: "vul-operator",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
						vuloperator.LabelVulnerabilityReportScanner: "Vul",
					},
				}},
			).Build()

			instance := jobs.NewLimitChecker(config, client, defaultVulOperatorConfig)
			limitExceeded, jobsCount, err := instance.Check(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeTrue())
			Expect(jobsCount).To(Equal(3))
		})

	})

	Context("When there are less jobs than limit", func() {

		It("Should return false", func() {
			client := fake.NewClientBuilder().WithScheme(vuloperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "vul-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash1",
					Namespace: "vul-operator",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
						vuloperator.LabelVulnerabilityReportScanner: "Vul",
					},
				}},
			).Build()

			instance := jobs.NewLimitChecker(config, client, defaultVulOperatorConfig)
			limitExceeded, jobsCount, err := instance.Check(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeFalse())
			Expect(jobsCount).To(Equal(1))
		})

	})

	Context("When there are more jobs than limit running in different namespace", func() {

		It("Should return true", func() {
			client := fake.NewClientBuilder().WithScheme(vuloperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "vul-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash1",
					Namespace: "default",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
						vuloperator.LabelVulnerabilityReportScanner: "Vul",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash2",
					Namespace: "prod",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
						vuloperator.LabelVulnerabilityReportScanner: "Vul",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-configauditreport-hash3",
					Namespace: "stage",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
						vuloperator.LabelVulnerabilityReportScanner: "Vul",
					},
				}},
			).Build()
			vulOperatorConfig := defaultVulOperatorConfig
			vulOperatorConfig[vuloperator.KeyVulnerabilityScansInSameNamespace] = "true"
			instance := jobs.NewLimitChecker(config, client, vulOperatorConfig)
			limitExceeded, jobsCount, err := instance.Check(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeTrue())
			Expect(jobsCount).To(Equal(3))
		})

	})

	Context("When there are more node collector jobs than limit", func() {

		It("Should return true", func() {

			client := fake.NewClientBuilder().WithScheme(vuloperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "vul-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "node-collector-hash1",
					Namespace: "vul-operator",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:   vuloperator.AppVulOperator,
						vuloperator.LabelNodeInfoCollector: "Vul",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "node-collector-hash2",
					Namespace: "vul-operator",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:   vuloperator.AppVulOperator,
						vuloperator.LabelNodeInfoCollector: "Vul",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "node-collector-hash3",
					Namespace: "vul-operator",
					Labels: map[string]string{
						vuloperator.LabelK8SAppManagedBy:   vuloperator.AppVulOperator,
						vuloperator.LabelNodeInfoCollector: "Vul",
					},
				}},
			).Build()

			instance := jobs.NewLimitChecker(config, client, defaultVulOperatorConfig)
			limitExceeded, jobsCount, err := instance.CheckNodes(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeTrue())
			Expect(jobsCount).To(Equal(3))
		})

	})

	Context("When there are less node collector jobs than limit", func() {

		It("Should return false", func() {
			client := fake.NewClientBuilder().WithScheme(vuloperator.NewScheme()).WithObjects().Build()

			instance := jobs.NewLimitChecker(config, client, defaultVulOperatorConfig)
			limitExceeded, jobsCount, err := instance.CheckNodes(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeFalse())
			Expect(jobsCount).To(Equal(0))
		})

	})

})
