package vul_test

import (
	"testing"

	"github.com/khulnasoft-lab/vul-operator/pkg/plugins/vul"
	"github.com/khulnasoft-lab/vul-operator/pkg/vuloperator"
	"github.com/stretchr/testify/assert"
)

func TestSlow(t *testing.T) {
	testCases := []struct {
		name       string
		configData vuloperator.ConfigData
		want       string
	}{{

		name: "slow param set to true",
		configData: map[string]string{
			"vul.tag":  "0.35.0",
			"vul.slow": "true",
		},
		want: "--slow",
	},
		{
			name: "slow param set to false",
			configData: map[string]string{
				"vul.tag":  "0.35.0",
				"vul.slow": "false",
			},
			want: "",
		},
		{
			name: "slow param set to no valid value",
			configData: map[string]string{
				"vul.tag":  "0.35.0",
				"vul.slow": "false2",
			},
			want: "--slow",
		},
		{
			name: "slow param set to true and vul tag is less then 0.35.0",
			configData: map[string]string{
				"vul.slow": "true",
				"vul.tag":  "0.33.0",
			},
			want: "",
		},

		{
			name: "slow param set to true and vul tag is bigger then 0.35.0",
			configData: map[string]string{
				"vul.slow": "true",
				"vul.tag":  "0.36.0",
			},
			want: "--slow",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := vul.Slow(vul.Config{vuloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestScanner(t *testing.T) {
	testCases := []struct {
		name       string
		configData vuloperator.ConfigData
		want       string
	}{{

		name: "scanner with vul tag lower then v0.37.0",
		configData: map[string]string{
			"vul.tag": "0.36.0",
		},
		want: "--security-checks",
	},
		{
			name: "scanner with vul tag equal then v0.37.0",
			configData: map[string]string{
				"vul.tag": "0.37.0",
			},
			want: "--scanners",
		},
		{
			name: "scanner with vul tag higher then v0.38.0",
			configData: map[string]string{
				"vul.tag": "0.38.0",
			},
			want: "--scanners",
		},
		{
			name:       "scanner with no vul tag lower",
			configData: map[string]string{},
			want:       "--scanners",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := vul.Scanners(vul.Config{vuloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestSkipDBUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData vuloperator.ConfigData
		want       string
	}{{

		name: "skip update DB with vul tag lower then v0.37.0",
		configData: map[string]string{
			"vul.tag": "0.36.0",
		},
		want: "--skip-update",
	},
		{
			name: "skip update DB with vul tag equal then v0.37.0",
			configData: map[string]string{
				"vul.tag": "0.37.0",
			},
			want: "--skip-db-update",
		},
		{
			name: "skip update DB with vul tag higher then v0.37.0",
			configData: map[string]string{
				"vul.tag": "0.38.0",
			},
			want: "--skip-db-update",
		},
		{
			name:       "skip update DB with no vul tag lower",
			configData: map[string]string{},
			want:       "--skip-db-update",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := vul.SkipDBUpdate(vul.Config{vuloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestSkipJavaDBUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData vuloperator.ConfigData
		want       string
	}{
		{
			name: "skip update Java DB with vul tag lower then v0.37.0",
			configData: map[string]string{
				"vul.skipJavaDBUpdate": "true",
				"vul.tag":              "0.36.0",
			},
			want: "",
		},
		{
			name: "skip update Java DB with vul tag equal to v0.37.0",
			configData: map[string]string{
				"vul.skipJavaDBUpdate": "true",
				"vul.tag":              "0.37.0",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with vul tag higher then v0.37.0",
			configData: map[string]string{
				"vul.skipJavaDBUpdate": "true",
				"vul.tag":              "0.38.0",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with no vul tag",
			configData: map[string]string{
				"vul.skipJavaDBUpdate": "true",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with skip false",
			configData: map[string]string{
				"vul.skipJavaDBUpdate": "false",
			},
			want: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := vul.SkipJavaDBUpdate(vul.Config{vuloperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, got, tc.want)
		})
	}
}
