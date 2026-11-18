package hostmetrics

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOTLPJSONProducerPreservesHostIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan map[string]any, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/metrics" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad wire request %+v", r)
			w.WriteHeader(400)
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		got <- raw
	})}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())
	t.Setenv("KS_HOST_OTLP_SOCKET", path)
	publisher := New("connector-ctl", "connector", map[string]string{"switch": "sw1"})
	a, b := uint64(123), uint64(0)
	now := time.Now().UTC()
	if err := publisher.Send(context.Background(), []Point{
		{Name: "connector.port.mgmt.rx.bytes", Unit: "By", Time: now, Uint: &a, Attributes: map[string]string{"port": "4", "generation": "5"}},
		{Name: "connector.port.mgmt.rx.bytes", Unit: "By", Time: now, Uint: &b, Attributes: map[string]string{"port": "5", "generation": "6"}},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-got:
		resources := payload["resourceMetrics"].([]any)
		if len(resources) != 1 {
			t.Fatalf("resource groups %d", len(resources))
		}
		resource := resources[0].(map[string]any)["resource"].(map[string]any)
		attrs := map[string]string{}
		for _, a := range resource["attributes"].([]any) {
			aa := a.(map[string]any)
			attrs[aa["key"].(string)] = aa["value"].(map[string]any)["stringValue"].(string)
		}
		for k, want := range map[string]string{"service.name": "connector-ctl", "sandbox.telemetry.source": "connector", "switch": "sw1"} {
			if attrs[k] != want {
				t.Errorf("attribute %s=%s want %s", k, attrs[k], want)
			}
		}
		if _, exists := attrs["sandbox.id"]; exists {
			t.Error("fabricated SID")
		}
		scopes := resources[0].(map[string]any)["scopeMetrics"].([]any)
		metrics := scopes[0].(map[string]any)["metrics"].([]any)
		if len(metrics) != 1 {
			t.Fatalf("metrics=%d", len(metrics))
		}
		points := metrics[0].(map[string]any)["gauge"].(map[string]any)["dataPoints"].([]any)
		if len(points) != 2 {
			t.Fatalf("points=%d", len(points))
		}
		if points[0].(map[string]any)["asInt"] != "123" || points[1].(map[string]any)["asInt"] != "0" {
			t.Errorf("integer metrics %#v", points)
		}
	case <-time.After(time.Second):
		t.Fatal("no receiver sample")
	}
}

func TestMissingSocketAndBadInputAreBounded(t *testing.T) {
	t.Setenv("KS_HOST_OTLP_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
	p := New("store-ctl", "store", nil)
	start := time.Now()
	if err := p.Send(context.Background(), []Point{{Name: "store.requests", Time: time.Now(), Value: 1}}); err == nil {
		t.Fatal("missing socket accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("blocked on missing telemetry")
	}
	if err := p.Send(context.Background(), []Point{{Name: "x", Time: time.Now(), Value: math.NaN()}}); err == nil {
		t.Fatal("invalid sample accepted")
	}
}

func TestOTLPPartialSuccess(t *testing.T) {
	for _, test := range []struct {
		name, body string
		rejected   bool
	}{
		{"warning", `{"partialSuccess":{"errorMessage":"warning"}}`, false},
		{"partial", `{"partialSuccess":{"rejectedDataPoints":"1","errorMessage":"invalid point"}}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "host.sock")
			ln, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.body)
			})}
			go srv.Serve(ln)
			defer srv.Close()
			t.Setenv("KS_HOST_OTLP_SOCKET", path)
			p := New("test", "test", nil)
			err = p.Send(t.Context(), []Point{{Name: "test.example", Time: time.Now(), Value: 1}})
			if test.rejected && (err == nil || !strings.Contains(err.Error(), "invalid point")) {
				t.Fatalf("expected rejected data point, got %v", err)
			}
			if !test.rejected && err != nil {
				t.Fatal(err)
			}
		})
	}
}
