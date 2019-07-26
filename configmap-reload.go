package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	fsnotify "github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
)

const namespace = "configmap_reload"

var (
	volumeDirs        volumeDirsFlag
	webhook           webhookFlag
	webhookMethod     = flag.String("webhook-method", "POST", "the HTTP method url to use to send the webhook")
	webhookStatusCode = flag.Int("webhook-status-code", 200, "the HTTP status code indicating successful triggering of reload")
	listenAddress     = flag.String("web.listen-address", ":9533", "Address to listen on for web interface and telemetry.")
	metricPath        = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	secretPath        = flag.String("secret-path", "", "YAML file containing to be passed as go-template values")
	templateFile      = flag.String("template-file", "", "Template file to render, relative to the volume dir")
	outputVolumeDir   = flag.String("output-dir", "", "Output directory for processed templates")
	useEnv            = flag.Bool("use-env", false, "When set to true, will use env vars instead of a secret file")

	lastReloadError = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "last_reload_error",
		Help:      "Whether the last reload resulted in an error (1 for error, 0 for success)",
	}, []string{"webhook"})
	requestDuration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "last_request_duration_seconds",
		Help:      "Duration of last webhook request",
	}, []string{"webhook"})
	successReloads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "success_reloads_total",
		Help:      "Total success reload calls",
	}, []string{"webhook"})
	requestErrorsByReason = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "request_errors_total",
		Help:      "Total request errors by reason",
	}, []string{"webhook", "reason"})
	watcherErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "watcher_errors_total",
		Help:      "Total filesystem watcher errors",
	})
	requestsByStatusCode = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "requests_total",
		Help:      "Total requests by response status code",
	}, []string{"webhook", "status_code"})
)

// Secret is an interface to secret providers
type Secret interface {
	Get() (interface{}, error)
}

// YAMLFileSecret is a YAML file secret interface
type YAMLFileSecret struct {
	file string
}

// NewYAMLFileSecret returns a new yaml file backed secret interface
func NewYAMLFileSecret(file string) *YAMLFileSecret {
	return &YAMLFileSecret{file}
}

// Get returns an interface{} of the contents of a yaml file
func (*YAMLFileSecret) Get() (interface{}, error) {
	var inf interface{}
	b, err := ioutil.ReadFile(*secretPath)
	if err != nil {
		return "", fmt.Errorf("failed to read secret file: %v", err)
	}

	if err := yaml.Unmarshal(b, &inf); err != nil {
		return "", fmt.Errorf("failed to unmarshall secret file: %v", err)
	}
	return inf, nil
}

// EnvSecret is a env secret interface
type EnvSecret struct{}

// NewEnvSecret returns a new env backed secret interface
// env should be the same format as os.Environ
func NewEnvSecret(env []string) *EnvSecret {
	return &EnvSecret{}
}

// Get returns a map[string]string of key value pair of the env vars
func (*EnvSecret) Get() (interface{}, error) {
	keys := make(map[string]string)
	for _, v := range os.Environ() {
		splits := strings.SplitN(v, "=", 2)
		// set KEY=VALUE supporting = in value
		keys[splits[0]] = splits[1]
	}
	return keys, nil
}

func init() {
	prometheus.MustRegister(lastReloadError)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(successReloads)
	prometheus.MustRegister(requestErrorsByReason)
	prometheus.MustRegister(watcherErrors)
	prometheus.MustRegister(requestsByStatusCode)
}

// generateNewConf returns a fully rendered configuration file with support
// for golang templating
func generateNewConf(templatePath string) (string, error) {
	rel, err := filepath.Rel(volumeDirs[0], templatePath)
	if err != nil {
		return "", err
	}

	// if it's not the template file we want, then we just return the raw contents
	// this also doubles as not running without a template file being set.
	if rel != *templateFile {
		b, err := ioutil.ReadFile(templatePath)
		if err != nil {
			return "", fmt.Errorf("failed to read file: %v", err)
		}
		return string(b), nil
	}

	log.Printf("rendering file '%s'", templatePath)
	b, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	t := template.New("conf")
	tmpl, err := t.Parse(string(b))
	if err != nil {
		return "", fmt.Errorf("failed to create template: %v", err)
	}

	var secret Secret

	if *useEnv {
		secret = NewEnvSecret(os.Environ())
	} else {
		secret = NewYAMLFileSecret(*secretPath)
	}

	inf, err := secret.Get()
	if err != nil {
		return "", fmt.Errorf("failed to get secret information: %v", err)
	}

	var resp bytes.Buffer
	if err := tmpl.Execute(&resp, inf); err != nil {
		return "", fmt.Errorf("failed to render template: %v", err)
	}
	return resp.String(), nil
}

// renderConfigs renders all configuration files
func renderConfigs() error {
	f, err := ioutil.ReadDir(*outputVolumeDir)
	if err != nil {
		return fmt.Errorf("failed to read outputVolumeDir: %v", err)
	}

	for _, o := range f {
		absPath := filepath.Join(*outputVolumeDir, o.Name())
		log.Println("cleaning up output dir", absPath)
		err := os.RemoveAll(absPath)
		if err != nil {
			log.Printf("WARN: failed to cleanup outputVolumeDir: %v", err)
		}
	}

	err = filepath.Walk(volumeDirs[0], func(path string, info os.FileInfo, err error) error {
		// failed to access the file, or some other unworkaroundable error
		if err != nil {
			return err
		}

		if info.IsDir() {
			log.Println("skipping dir", path)
			return nil
		}

		s, err := generateNewConf(path)
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(volumeDirs[0], path)
		if err != nil {
			return err
		}

		savePath := filepath.Join(*outputVolumeDir, rel)

		err = ioutil.WriteFile(savePath, []byte(s), info.Mode())
		return err
	})
	return err
}

func main() {
	flag.Var(&volumeDirs, "volume-dir", "the config map volume directory to watch for updates; may be used multiple times")
	flag.Var(&webhook, "webhook-url", "the url to send a request to when the specified config map volume directory has been updated")
	flag.Parse()

	if len(volumeDirs) < 1 {
		log.Println("Missing volume-dir")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	if len(webhook) < 1 {
		log.Println("Missing webhook-url")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	// why template without secrets?
	if *templateFile != "" && *secretPath == "" && !*useEnv {
		log.Println("secretPath must be set when using templateFile")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	if *secretPath != "" && *useEnv {
		log.Println("secretPath can't be set when useEnv is set")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	// only support output volumes in templateFile mode
	if *outputVolumeDir != "" && *templateFile == "" {
		log.Println("outputVolumeDir is only support when in templating mode")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	// can only output to one dir, so only support one dir
	if *outputVolumeDir != "" && len(volumeDirs) > 1 {
		log.Println("only one volumeDir can be set when outputVolumeDir is set")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	if *outputVolumeDir != "" {
		if err := os.MkdirAll(*outputVolumeDir, 0777); err != nil {
			log.Fatalf("failed to ensure outputVolumeDir existed: %v", err)
		}
	}

	renderConfigs()

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if !isValidEvent(event) {
					log.Printf("skipping invalid event: %v", event)
					continue
				}
				log.Println("config map updated")

				err := renderConfigs()
				if err != nil {
					log.Printf("ERROR: failed to render configuration: %v", err)
					continue
				}

				for _, h := range webhook {
					begun := time.Now()
					req, err := http.NewRequest(*webhookMethod, h.String(), nil)
					if err != nil {
						setFailureMetrics(h.String(), "client_request_create")
						log.Println("error:", err)
						continue
					}
					userInfo := h.User
					if userInfo != nil {
						if password, passwordSet := userInfo.Password(); passwordSet {
							req.SetBasicAuth(userInfo.Username(), password)
						}
					}
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						setFailureMetrics(h.String(), "client_request_do")
						log.Println("error:", err)
						continue
					}
					resp.Body.Close()
					requestsByStatusCode.WithLabelValues(h.String(), strconv.Itoa(resp.StatusCode)).Inc()
					if resp.StatusCode != *webhookStatusCode {
						setFailureMetrics(h.String(), "client_response")
						log.Println("error:", "Received response code", resp.StatusCode, ", expected", *webhookStatusCode)
						continue
					}
					setSuccessMetrics(h.String(), begun)
					log.Println("successfully triggered reload")
				}
			case err := <-watcher.Errors:
				watcherErrors.Inc()
				log.Println("error:", err)
			}
		}
	}()

	for _, d := range volumeDirs {
		log.Printf("Watching directory: '%s'", d)
		if err = watcher.Add(d); err != nil {
			log.Fatal(err)
		}
	}

	log.Fatal(serverMetrics(*listenAddress, *metricPath))
}

func setFailureMetrics(h, reason string) {
	requestErrorsByReason.WithLabelValues(h, reason).Inc()
	lastReloadError.WithLabelValues(h).Set(1.0)
}

func setSuccessMetrics(h string, begun time.Time) {
	requestDuration.WithLabelValues(h).Set(time.Since(begun).Seconds())
	successReloads.WithLabelValues(h).Inc()
	lastReloadError.WithLabelValues(h).Set(0.0)
}

func isValidEvent(event fsnotify.Event) bool {
	// for testing, have this return true
	// return true
	if event.Op&fsnotify.Create != fsnotify.Create {
		return false
	}
	if filepath.Base(event.Name) != "..data" {
		return false
	}
	return true
}

func serverMetrics(listenAddress, metricsPath string) error {
	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>ConfigMap Reload Metrics</title></head>
			<body>
			<h1>ConfigMap Reload</h1>
			<p><a href='` + metricsPath + `'>Metrics</a></p>
			</body>
			</html>
		`))
	})
	return http.ListenAndServe(listenAddress, nil)
}

type volumeDirsFlag []string

type webhookFlag []*url.URL

func (v *volumeDirsFlag) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func (v *volumeDirsFlag) String() string {
	return fmt.Sprint(*v)
}

func (v *webhookFlag) Set(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	*v = append(*v, u)
	return nil
}

func (v *webhookFlag) String() string {
	return fmt.Sprint(*v)
}
