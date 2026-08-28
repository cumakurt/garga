package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	dockerRunTimeout  = 30 * time.Second
	dockerPullTimeout = 10 * time.Minute
	dockerLogsTimeout = 15 * time.Second
	dockerRMTimeout   = 30 * time.Second
	clusterReadyWait  = 2*time.Minute + 30*time.Second
	passwordResetWait = 20 * time.Second
	readyPollInterval = 500 * time.Millisecond
	readySuccesses    = 2
	elasticsearchHeap = "-Xms512m -Xmx512m"
)

type esCluster struct {
	Lane     matrixLane
	Name     string
	Port     int
	Password string
	Certs    tlsMaterial
	secrets  []string
	envFile  string
}

func (cluster *esCluster) endpointHost() string { return "127.0.0.1" }

func (cluster *esCluster) redact(text string) string {
	return redactDiagnostics(text, cluster.secrets)
}

func startCluster(t *testing.T, lane matrixLane) *esCluster {
	t.Helper()
	requireDocker(t)

	password, err := randomPassword()
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}
	cluster := &esCluster{
		Lane:     lane,
		Name:     uniqueName(lane),
		Password: password,
		secrets:  []string{password},
	}

	port, err := freePort()
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	cluster.Port = port

	if err := ensureImage(t, lane.Image); err != nil {
		t.Fatalf("%s", cluster.redact(err.Error()))
	}

	if lane.TLS {
		material, certErr := generateTLSMaterial()
		if certErr != nil {
			t.Fatalf("tls material: %v", certErr)
		}
		cluster.Certs = material
		t.Cleanup(func() { _ = os.RemoveAll(material.Dir) })
		_ = chownCertsForElasticsearch(material.Dir)
	}

	args, envFile, err := dockerRunArgs(cluster)
	if err != nil {
		t.Fatalf("docker run args: %v", err)
	}
	cluster.envFile = envFile
	if envFile != "" {
		t.Cleanup(func() { _ = os.Remove(envFile) })
	}

	ctx, cancel := context.WithTimeout(context.Background(), dockerRunTimeout)
	defer cancel()
	stdout, stderr, err := docker(ctx, args...)
	if err != nil {
		t.Fatalf("docker run failed: %s\n%s", cluster.redact(err.Error()), cluster.redact(stderr+stdout))
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), dockerRMTimeout)
		defer stopCancel()
		_, _, _ = docker(stopCtx, "rm", "-f", cluster.Name)
	})

	if err := waitHealthy(t, cluster); err != nil {
		t.Fatalf("%s\n%s", cluster.redact(err.Error()), cluster.diagnostics())
	}
	return cluster
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("GARGA_INTEGRATION=1 requires docker in PATH: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, stderr, err := docker(ctx, "info")
	if err != nil {
		t.Fatalf("GARGA_INTEGRATION=1 requires a running Docker engine: %v\n%s", err, redactDiagnostics(stderr, nil))
	}
}

func ensureImage(t *testing.T, image string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, _, err := docker(ctx, "image", "inspect", image)
	cancel()
	if err == nil {
		return nil
	}
	t.Logf("pulling %s", image)
	pullCtx, pullCancel := context.WithTimeout(context.Background(), dockerPullTimeout)
	defer pullCancel()
	_, stderr, pullErr := docker(pullCtx, "pull", image)
	if pullErr != nil {
		return fmt.Errorf("docker pull %s: %w\n%s", image, pullErr, stderr)
	}
	return nil
}

func dockerRunArgs(cluster *esCluster) ([]string, string, error) {
	lane := cluster.Lane
	args := []string{
		"run", "-d",
		"--name", cluster.Name,
		"--memory", "2g",
		"-p", fmt.Sprintf("127.0.0.1:%d:9200", cluster.Port),
		"-e", "discovery.type=single-node",
		"-e", "ES_JAVA_OPTS=" + elasticsearchHeap,
		"-e", "ingest.geoip.downloader.enabled=false",
		"-e", "node.store.allow_mmap=false",
		"-e", "cluster.routing.allocation.disk.threshold_enabled=false",
	}
	if lane.major() >= 8 {
		args = append(args,
			"-e", "xpack.security.enrollment.enabled=false",
			"-e", "xpack.security.autoconfiguration.enabled=false",
			"-e", "xpack.security.transport.ssl.enabled=false",
			"-e", "xpack.ml.enabled=false",
		)
	}
	if lane.Auth {
		args = append(args, "-e", "xpack.security.enabled=true")
	} else {
		args = append(args, "-e", "xpack.security.enabled=false")
	}
	if lane.TLS {
		if cluster.Certs.Dir == "" {
			return nil, "", fmt.Errorf("tls lane missing certificate directory")
		}
		args = append(args,
			"-v", cluster.Certs.Dir+":/usr/share/elasticsearch/config/certs:ro",
			"-e", "xpack.security.http.ssl.enabled=true",
			"-e", "xpack.security.http.ssl.key=/usr/share/elasticsearch/config/certs/http.key",
			"-e", "xpack.security.http.ssl.certificate=/usr/share/elasticsearch/config/certs/http.crt",
			"-e", "xpack.security.http.ssl.certificate_authorities=/usr/share/elasticsearch/config/certs/ca.crt",
			"-e", "xpack.security.http.ssl.client_authentication=none",
		)
	} else {
		args = append(args, "-e", "xpack.security.http.ssl.enabled=false")
	}

	var envFile string
	if lane.Auth {
		file, err := os.CreateTemp("", "garga-es-env-")
		if err != nil {
			return nil, "", err
		}
		if _, err := fmt.Fprintf(file, "ELASTIC_PASSWORD=%s\n", cluster.Password); err != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
			return nil, "", err
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(file.Name())
			return nil, "", err
		}
		if err := os.Chmod(file.Name(), 0600); err != nil {
			_ = os.Remove(file.Name())
			return nil, "", err
		}
		envFile = file.Name()
		args = append(args, "--env-file", envFile)
	}
	args = append(args, lane.Image)
	return args, envFile, nil
}

func waitHealthy(t *testing.T, cluster *esCluster) error {
	t.Helper()
	started := time.Now()
	deadline := started.Add(clusterReadyWait)
	var lastReset time.Time
	var last error
	consecutiveReady := 0
	for time.Now().Before(deadline) {
		if !containerRunning(cluster.Name) {
			return fmt.Errorf("container %s exited before becoming ready", cluster.Name)
		}
		err := probeReady(cluster)
		if err == nil {
			consecutiveReady++
			if consecutiveReady >= readySuccesses {
				return nil
			}
			time.Sleep(readyPollInterval)
			continue
		}
		consecutiveReady = 0
		last = err
		if cluster.Lane.Auth && time.Since(started) >= passwordResetWait &&
			(lastReset.IsZero() || time.Since(lastReset) >= passwordResetWait) {
			password, resetErr := resetElasticPassword(cluster)
			lastReset = time.Now()
			if resetErr != nil {
				last = resetErr
			} else {
				cluster.Password = password
			}
		}
		time.Sleep(readyPollInterval)
	}
	if last == nil {
		last = errors.New("timed out waiting for Elasticsearch")
	}
	return fmt.Errorf("elasticsearch %s not ready: %w", cluster.Lane.Image, last)
}

func containerRunning(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stdout, _, err := docker(ctx, "inspect", "-f", "{{.State.Running}}", name)
	if err != nil {
		return false
	}
	return strings.TrimSpace(stdout) == "true"
}

func (cluster *esCluster) diagnostics() string {
	ctx, cancel := context.WithTimeout(context.Background(), dockerLogsTimeout)
	defer cancel()
	stdout, stderr, err := docker(ctx, "logs", "--tail", "20", cluster.Name)
	var builder strings.Builder
	fmt.Fprintf(&builder, "image=%s container=%s port=%d auth=%t tls=%t\n",
		cluster.Lane.Image, cluster.Name, cluster.Port, cluster.Lane.Auth, cluster.Lane.TLS)
	if err != nil {
		fmt.Fprintf(&builder, "docker logs error: %s\n%s\n", err.Error(), stderr)
	}
	builder.WriteString(stdout)
	if stderr != "" {
		builder.WriteString(stderr)
	}
	inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer inspectCancel()
	status, _, _ := docker(inspectCtx, "inspect", "-f", "running={{.State.Running}} exit={{.State.ExitCode}} error={{.State.Error}}", cluster.Name)
	builder.WriteString(status)
	return cluster.redact(builder.String())
}

func docker(ctx context.Context, args ...string) (string, string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		if ctx.Err() != nil {
			return stdout.String(), stderr.String(), fmt.Errorf("docker %s: %w", args[0], ctx.Err())
		}
		return stdout.String(), stderr.String(), fmt.Errorf("docker %s: %w", args[0], err)
	}
	return stdout.String(), stderr.String(), nil
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func uniqueName(lane matrixLane) string {
	var suffix [4]byte
	_, _ = rand.Read(suffix[:])
	label := strings.ReplaceAll(lane.Version, ".", "")
	auth := "anon"
	if lane.Auth {
		auth = "auth"
	}
	transport := "http"
	if lane.TLS {
		transport = "tls"
	}
	return "garga-es-" + label + "-" + auth + "-" + transport + "-" + hex.EncodeToString(suffix[:])
}

func randomPassword() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "Garga-Int-" + hex.EncodeToString(raw[:]) + "!", nil
}

func chownCertsForElasticsearch(dir string) error {
	var first error
	for _, name := range []string{"ca.crt", "http.crt", "http.key"} {
		if err := os.Chown(filepath.Join(dir, name), 1000, 0); err != nil && first == nil {
			first = err
		}
	}
	if err := os.Chown(dir, 1000, 0); err != nil && first == nil {
		first = err
	}
	return first
}

func clusterStatusGreen(body []byte) bool {
	return bytes.Contains(body, []byte(`"status":"green"`))
}

func resetElasticPassword(cluster *esCluster) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stdout, stderr, err := docker(ctx, "exec", cluster.Name,
		"/usr/share/elasticsearch/bin/elasticsearch-reset-password", "-u", "elastic", "-b", "-a")
	output := stdout + stderr
	password := parseResetPassword(output)
	if password != "" {
		cluster.secrets = append(cluster.secrets, password)
	}
	if err != nil {
		return "", fmt.Errorf("elasticsearch-reset-password: %w\n%s", err, output)
	}
	if password == "" {
		return "", fmt.Errorf("elasticsearch-reset-password did not print a new value")
	}
	return password, nil
}

func parseResetPassword(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "New value:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
