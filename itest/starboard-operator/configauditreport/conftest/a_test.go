package conftest

import (
	. "github.com/khulnasoft-lab/starboard/itest/starboard-operator/behavior"
	. "github.com/onsi/ginkgo"
)

var _ = Describe("Conftest", ConfigurationCheckerBehavior(&inputs))
