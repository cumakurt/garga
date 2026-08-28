package secrets

import "testing"

func TestNormalAndDeepProfilesDiffer(t *testing.T) {
	t.Parallel()
	normal := NormalProfile()
	deep := DeepScanProfile()
	if normal.Mode != ScanModeNormal || deep.Mode != ScanModeDeep {
		t.Fatalf("modes = %s %s", normal.Mode, deep.Mode)
	}
	if deep.SampleSize <= normal.SampleSize {
		t.Fatalf("deep sample size %d should exceed normal %d", deep.SampleSize, normal.SampleSize)
	}
	if deep.MaxDocuments <= normal.MaxDocuments {
		t.Fatalf("deep max documents %d should exceed normal %d", deep.MaxDocuments, normal.MaxDocuments)
	}
	if deep.MaxFieldBytes <= normal.MaxFieldBytes || deep.MaxDepth <= normal.MaxDepth {
		t.Fatal("deep field/depth limits should exceed normal")
	}
	if !deep.ScanGenericFields || normal.ScanGenericFields {
		t.Fatal("generic field analysis is deep-only by default")
	}
	if !deep.BroadCorrelation || normal.BroadCorrelation {
		t.Fatal("broad correlation is deep-only by default")
	}
}

func TestDeepProfileStaysWithinHardCaps(t *testing.T) {
	t.Parallel()
	deep := DeepScanProfile()
	if deep.SampleSize > maxSampleSize || deep.MaxDocuments > maxDocuments {
		t.Fatalf("deep document limits exceed hard caps: sample=%d max=%d", deep.SampleSize, deep.MaxDocuments)
	}
	if deep.MaxFieldBytes > maxFieldBytes || deep.MaxDepth > maxDepth || deep.MaxArrayItems > maxArrayItems {
		t.Fatal("deep walk limits exceed hard caps")
	}
	if deep.MaxSourceFields > maxSourceFieldsCap || deep.SearchBatch > maxSearchBatch {
		t.Fatal("deep search limits exceed hard caps")
	}
	options := Options{SampleSize: 1, MaxDocuments: 1}
	ApplyProfile(&options, deep, ProfileOverrides{})
	if err := options.validate(); err != nil {
		t.Fatalf("deep profile failed validation: %v", err)
	}
	if options.SampleSize != deep.SampleSize || !options.DeepScan {
		t.Fatalf("ApplyProfile did not apply deep defaults: %+v", options)
	}
}

func TestApplyProfileKeepsOperatorOverrides(t *testing.T) {
	t.Parallel()
	options := Options{SampleSize: 12, MaxDocuments: 34, MaxDepth: 3}
	ApplyProfile(&options, DeepScanProfile(), ProfileOverrides{SampleSize: true, MaxDocuments: true, MaxDepth: true})
	if options.SampleSize != 12 || options.MaxDocuments != 34 || options.MaxDepth != 3 {
		t.Fatalf("overrides lost: %+v", options)
	}
	if !options.DeepScan || !options.ScanGenericFields || !options.BroadCorrelation {
		t.Fatalf("deep behavior flags missing: %+v", options)
	}
}

func TestSourceIncludesGenericFieldsOnlyInDeepProfile(t *testing.T) {
	t.Parallel()
	fields := []FieldSemantics{
		AnalyzeField("count"),
		{Path: "sku", Name: "sku", ESType: "keyword"},
		AnalyzeField("password"),
	}
	normal := sourceIncludes(fields, 8, false)
	if len(normal) == 0 || normal[0] != "password" {
		t.Fatalf("normal includes = %v", normal)
	}
	for _, name := range normal {
		if name == "sku" {
			t.Fatal("normal scan included generic keyword field")
		}
	}
	deep := sourceIncludes(fields, 8, true)
	found := false
	for _, name := range deep {
		if name == "sku" {
			found = true
		}
	}
	if !found {
		t.Fatalf("deep includes missing sku: %v", deep)
	}
}
