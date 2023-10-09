package compliance

import (
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/khulnasoft-lab/starboard/pkg/apis/khulnasoft/v1alpha1"
)

// mapKinds map resource data
func mapKinds(control v1alpha1.Control) []string {
	set := hashset.New()
	updatedKinds := make([]string, 0)
	for _, resource := range control.Kinds {
		if resource == "Workload" {
			set.Add("Pod", "ReplicationController", "ReplicaSet", "StatefulSet", "DaemonSet", "CronJob", "Job")
		} else {
			set.Add(resource)
		}
	}
	for _, setResource := range set.Values() {
		updatedKinds = append(updatedKinds, setResource.(string))
	}
	return updatedKinds
}
