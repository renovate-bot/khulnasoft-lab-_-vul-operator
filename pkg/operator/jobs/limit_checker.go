package jobs

import (
	"context"

	"github.com/khulnasoft-lab/vul-operator/pkg/operator/etc"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const ScannerName = "Vul"

type LimitChecker interface {
	Check(ctx context.Context) (bool, int, error)
	CheckNodes(ctx context.Context) (bool, int, error)
}

func NewLimitChecker(config etc.Config, c client.Client, vulOperatorConfig vuloperator.ConfigData) LimitChecker {
	return &checker{
		config:              config,
		client:              c,
		vulOperatorConfig: vulOperatorConfig,
	}
}

type checker struct {
	config              etc.Config
	client              client.Client
	vulOperatorConfig vuloperator.ConfigData
}

func (c *checker) Check(ctx context.Context) (bool, int, error) {
	matchinglabels := client.MatchingLabels{
		vuloperator.LabelK8SAppManagedBy:            vuloperator.AppVulOperator,
		vuloperator.LabelVulnerabilityReportScanner: ScannerName,
	}
	scanJobsCount, err := c.countJobs(ctx, matchinglabels)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentScanJobsLimit, scanJobsCount, nil
}

func (c *checker) CheckNodes(ctx context.Context) (bool, int, error) {
	matchinglabels := client.MatchingLabels{
		vuloperator.LabelK8SAppManagedBy:   vuloperator.AppVulOperator,
		vuloperator.LabelNodeInfoCollector: ScannerName,
	}
	scanJobsCount, err := c.countJobs(ctx, matchinglabels)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentNodeCollectorLimit, scanJobsCount, nil
}

func (c *checker) countJobs(ctx context.Context, matchingLabels client.MatchingLabels) (int, error) {
	var scanJobs batchv1.JobList
	listOptions := []client.ListOption{matchingLabels}
	if !c.vulOperatorConfig.VulnerabilityScanJobsInSameNamespace() {
		// scan jobs are running in only vuloperator operator namespace
		listOptions = append(listOptions, client.InNamespace(c.config.Namespace))
	}
	err := c.client.List(ctx, &scanJobs, listOptions...)
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}
