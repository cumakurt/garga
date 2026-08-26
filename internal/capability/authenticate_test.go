package capability

import "testing"

func TestParseAnonymousSuperuser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"superuser", `{"username":"credential-canary","roles":["superuser"]}`, true},
		{"mixed roles", `{"roles":["monitoring_user","superuser"]}`, true},
		{"case", `{"roles":["SuperUser"]}`, true},
		{"viewer", `{"roles":["viewer"]}`, false},
		{"custom canary", `{"username":"credential-canary","roles":["credential-canary"]}`, false},
		{"missing roles", `{"username":"anonymous"}`, false},
		{"trailing", `{"roles":["superuser"]} {}`, false},
		{"malformed", `{`, false},
		{"empty", ``, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := parseAnonymousSuperuser([]byte(test.body)); got != test.want {
				t.Fatalf("parseAnonymousSuperuser() = %t, want %t", got, test.want)
			}
		})
	}
}

func FuzzParseAnonymousSuperuser(f *testing.F) {
	f.Add([]byte(`{"roles":["superuser"]}`))
	f.Add([]byte(`{"username":"x","roles":["viewer"]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64*1024 {
			t.Skip()
		}
		_ = parseAnonymousSuperuser(body)
	})
}
