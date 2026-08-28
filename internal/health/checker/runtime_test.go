package checker

import (
	"context"
	"testing"

	"github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/vulnerability"
)

func TestNodeRuntimeDriftFindsVersionJVMAndComponentDifferences(t *testing.T) {
	t.Parallel()
	snapshot := &model.ClusterSnapshot{
		Cluster: model.ClusterInfo{Name: "fixture", Version: model.Version{Number: "9.5.2"}},
		Nodes: []model.Node{
			{Name: "node-a", Version: "9.5.2", JVM: model.JVMStats{Version: "21.0.4", Vendor: "A"}, Components: []model.NodeComponent{{Name: "repository-s3", Type: "plugin"}}},
			{Name: "node-b", Version: "9.4.5", JVM: model.JVMStats{Version: "21.0.3", Vendor: "B"}},
		},
		Collection: model.CollectionState{Collectors: []model.CollectorResult{{Name: "nodes_info", Status: "success"}}},
	}
	findings, err := nodeRuntimeDrift().Check(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestVulnerabilityCheckerUsesRuntimePrerequisites(t *testing.T) {
	t.Parallel()
	signature, err := vulnerability.Parse("fixture.yaml", []byte(`
schema_version: "0.1"
id: garga.vuln.context-fixture
title: Context fixture
severity: high
cve: [CVE-2099-10001]
product: elasticsearch
affected: [">=9.4.0 <9.5.0"]
applicability:
  components_any: [ingest-attachment]
  realms_any: [oidc]
  jvm_major_max: 21
detection: version
remediation: Upgrade.
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	snapshot := &model.ClusterSnapshot{
		Target: "https://es.example:9200/", Cluster: model.ClusterInfo{Name: "fixture", Version: model.Version{Number: "9.4.4"}, FingerprintValid: true},
		Nodes: []model.Node{{Name: "node-a", JVM: model.JVMStats{Version: "21.0.4"}, Components: []model.NodeComponent{{Name: "ingest-attachment", Type: "module"}}, SecuritySettings: map[string]string{"xpack.security.authc.realms.oidc.main.order": "0"}}},
		Collection: model.CollectionState{Collectors: []model.CollectorResult{
			{Name: "nodes_info", Status: "success"}, {Name: "nodes_settings", Status: "success"}, {Name: "cluster_settings", Status: "success"},
		}},
	}
	findings, err := vulnerabilitySignatures([]vulnerability.Signature{signature}).Check(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Confidence != model.ConfidenceHigh || findings[0].Evidence["applicability"] != "applicable" {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestRuntimeContextDoesNotClaimEmptyNodeInventoryIsKnown(t *testing.T) {
	t.Parallel()

	snapshot := &model.ClusterSnapshot{Collection: model.CollectionState{Collectors: []model.CollectorResult{
		{Name: "nodes_info", Status: "success"},
		{Name: "nodes_settings", Status: "success"},
		{Name: "cluster_settings", Status: "success"},
	}}}
	context := runtimeContext(snapshot)
	if context.ComponentsKnown || context.JVMKnown || context.RealmsKnown || context.SettingsKnown {
		t.Fatalf("empty runtime inventory marked known: %#v", context)
	}
}

func TestVulnerabilityCheckerKeepsConflictingNodeSettingPotential(t *testing.T) {
	t.Parallel()

	signature, err := vulnerability.Parse("fixture.yaml", []byte(`
schema_version: "0.1"
id: garga.vuln.setting-conflict
title: Setting conflict fixture
severity: high
cve: [CVE-2099-10002]
product: elasticsearch
affected: [">=9.4.0 <9.5.0"]
applicability:
  settings_all:
    xpack.security.enabled: "true"
detection: version
remediation: Upgrade.
`))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &model.ClusterSnapshot{
		Target:  "https://es.example:9200/",
		Cluster: model.ClusterInfo{Version: model.Version{Number: "9.4.4"}, FingerprintValid: true},
		Nodes: []model.Node{
			{Name: "node-a", SecuritySettings: map[string]string{"xpack.security.enabled": "true"}},
			{Name: "node-b", SecuritySettings: map[string]string{"xpack.security.enabled": "false"}},
		},
		Collection: model.CollectionState{Collectors: []model.CollectorResult{
			{Name: "nodes_info", Status: "success"},
			{Name: "nodes_settings", Status: "success"},
			{Name: "cluster_settings", Status: "success"},
		}},
	}
	findings, err := vulnerabilitySignatures([]vulnerability.Signature{signature}).Check(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Evidence["applicability"] != "potential" {
		t.Fatalf("findings = %#v", findings)
	}
}
