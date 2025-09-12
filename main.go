package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ================== Config ==================

const (
	defaultPort = "8080"
)

var apiEndpoints = map[string]string{
	"organizations":   "https://organization-manager.api.cloud.yandex.net/organization-manager/v1/organizations",
	"billingAccounts": "https://billing.api.cloud.yandex.net/billing/v1/billingAccounts",
	"clouds":          "https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds",
	"quotaServices":   "https://quota-manager.api.cloud.yandex.net/quota-manager/v1/quotaLimits/services",
	"quotaLimits":     "https://quota-manager.api.cloud.yandex.net/quota-manager/v1/quotaLimits",
}

// ================== HTTP client ==================

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

// ================== Prometheus metrics ==================

var (
	quotaUsageGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "yandex_quota_usage",
			Help: "Current quota usage for Yandex Cloud resources.",
		},
		[]string{
			"resource_label_key", "resource_id", "service", "quota_id", "resource_type",
			"org_id", "cloud_id", "org_name", "cloud_name",
		},
	)

	quotaLimitGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "yandex_quota_limit",
			Help: "Current quota limits for Yandex Cloud resources.",
		},
		[]string{
			"resource_label_key", "resource_id", "service", "quota_id", "resource_type",
			"org_id", "cloud_id", "org_name", "cloud_name",
		},
	)

	lastScrapeStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "yandex_quota_scrape_success",
			Help: "1 if the last scrape succeeded, 0 otherwise.",
		},
	)

	lastScrapeTs = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "yandex_quota_scrape_timestamp_seconds",
			Help: "Unix time of last successful scrape.",
		},
	)
)

func init() {
	prometheus.MustRegister(quotaUsageGauge, quotaLimitGauge, lastScrapeStatus, lastScrapeTs)
}

// ================== Types ==================

// Организация
type orgItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type listOrganizationsResp struct {
	Organizations []orgItem `json:"organizations"`
}

// Облако
type cloudItem struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	OrganizationID string `json:"organizationId"`
}

type listCloudsResp struct {
	Clouds []cloudItem `json:"clouds"`
}

// Биллинг-аккаунты: нужен только id
type idOnly struct {
	ID string `json:"id"`
}
type listBillingResp struct {
	BillingAccounts []idOnly `json:"billingAccounts"`
}

// Сервисы квот
type quotaService struct {
	ID string `json:"id"`
}
type quotaServicesResp struct {
	Services []quotaService `json:"services"`
}

// Квоты
type QuotaLimit struct {
	QuotaID string   `json:"quotaId"`
	Limit   *float64 `json:"limit"`
	Usage   *float64 `json:"usage"`
}

type quotaLimitsResp struct {
	QuotaLimits []QuotaLimit `json:"quotaLimits"`
}

// ================== Helpers ==================

func envTrue(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return v == "true" || v == "1" || v == "yes" || v == "y"
}

func quietBenign() bool { return envTrue("QUIET_BENIGN") }

// ================== IAM token ==================

func getIAMToken(_ context.Context) (string, error) {
	path := strings.TrimSpace(os.Getenv("YC_IAM_TOKEN_FILE"))
	if path == "" {
		return "", errors.New("YC_IAM_TOKEN_FILE not set")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}

	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("token file is empty")
	}

	return tok, nil
}

// ================== Error helpers ==================

type apiError struct {
	Status     int
	Code       int
	Message    string
	RawSnippet string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("status %d code %d: %s", e.Status, e.Code, e.Message)
}

func (e *apiError) isBenignUnsupported() bool {
	msg := strings.ToLower(e.Message)
	if e.Status == 400 && (strings.Contains(msg, "does not support quotas") || strings.Contains(msg, "unsupported")) {
		return true
	}
	if e.Status == 404 && (strings.Contains(msg, "notfound") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no rows in result set") ||
		strings.Contains(msg, "no activated backup providers")) {
		return true
	}
	return false
}

// ================== Generic GET ==================

func apiGET(ctx context.Context, endpoint string, bearer string, params map[string]string, out interface{}) error {
	u, _ := url.Parse(endpoint)
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", u.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		const maxErrBody = 2048
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		ae := &apiError{Status: resp.StatusCode, RawSnippet: string(b)}
		var j struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &j)
		ae.Code, ae.Message = j.Code, j.Message
		return ae
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ================== Core scrape ==================

type resource struct {
	id           string
	resourceType string
	labelKey     string
	orgID        string
	cloudID      string
	orgName      string
	cloudName    string
}

func listResources(ctx context.Context, bearer string, billingIDs []string) ([]resource, error) {
	var res []resource

	enableOrg := envTrue("ENABLE_ORG")
	enableCloud := envTrue("ENABLE_CLOUD")
	enableBilling := envTrue("ENABLE_BILLING")

	if !enableOrg && !enableCloud && !enableBilling {
		return res, nil
	}

	// 1) Организации (и словарь id->name для облаков)
	orgNames := map[string]string{}
	if enableOrg || enableCloud {
		var orgs listOrganizationsResp
		if err := apiGET(ctx, apiEndpoints["organizations"], bearer, nil, &orgs); err == nil {
			for _, o := range orgs.Organizations {
				orgNames[o.ID] = o.Name
				if enableOrg {
					res = append(res, resource{
						id:           o.ID,
						resourceType: "organization-manager.organization",
						labelKey:     "org_id",
						orgID:        o.ID,
						orgName:      o.Name,
					})
				}
			}
		} else {
			log.Printf("warn: organizations: %v", err)
		}
	}

	// 2) Облака
	if enableCloud {
		var clouds listCloudsResp
		if err := apiGET(ctx, apiEndpoints["clouds"], bearer, nil, &clouds); err == nil {
			for _, c := range clouds.Clouds {
				res = append(res, resource{
					id:           c.ID,
					resourceType: "resource-manager.cloud",
					labelKey:     "cloud_id",
					cloudID:      c.ID,
					cloudName:    c.Name,
					orgID:        c.OrganizationID,
					orgName:      orgNames[c.OrganizationID],
				})
			}
		} else {
			log.Printf("warn: clouds: %v", err)
		}
	}

	// 3) Биллинг
	if enableBilling {
		if len(billingIDs) == 0 {
			var bl listBillingResp
			if err := apiGET(ctx, apiEndpoints["billingAccounts"], bearer, nil, &bl); err == nil {
				for _, b := range bl.BillingAccounts {
					res = append(res, resource{
						id:           b.ID,
						resourceType: "billing.account",
						labelKey:     "billing_account_id",
					})
				}
			} else {
				log.Printf("warn: billingAccounts: %v", err)
			}
		} else {
			for _, id := range billingIDs {
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				res = append(res, resource{
					id:           id,
					resourceType: "billing.account",
					labelKey:     "billing_account_id",
				})
			}
		}
	}

	return res, nil
}

func listServices(ctx context.Context, bearer, resourceType string) ([]string, error) {
	var resp quotaServicesResp
	if err := apiGET(ctx, apiEndpoints["quotaServices"], bearer, map[string]string{
		"resourceType": resourceType,
	}, &resp); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.Services))
	for _, s := range resp.Services {
		if s.ID != "" {
			out = append(out, s.ID)
		}
	}
	return out, nil
}

// Кэш неподдерживаемых пар: resourceType -> service -> true
var unsupported = map[string]map[string]bool{}

func markUnsupported(rt, svc string) {
	m, ok := unsupported[rt]
	if !ok {
		m = map[string]bool{}
		unsupported[rt] = m
	}
	m[svc] = true
}
func isUnsupported(rt, svc string) bool {
	if m, ok := unsupported[rt]; ok {
		return m[svc]
	}
	return false
}

func scrapeOnce(ctx context.Context) error {
	token, err := getIAMToken(ctx)
	if err != nil {
		return err
	}

	var billingIDs []string
	if v := os.Getenv("BILLING_ID"); v != "" {
		for _, p := range strings.Split(v, ",") {
			if s := strings.TrimSpace(p); s != "" {
				billingIDs = append(billingIDs, s)
			}
		}
	}

	resources, err := listResources(ctx, token, billingIDs)
	if err != nil {
		return err
	}

	quotaUsageGauge.Reset()
	quotaLimitGauge.Reset()

	servicesCache := map[string][]string{}

	for _, r := range resources {
		// получаем список сервисов
		var svcs []string
		if cached, ok := servicesCache[r.resourceType]; ok {
			svcs = cached
		} else {
			if r.resourceType == "billing.account" {
				svcs = []string{"billing"}
			} else {
				c, err := listServices(ctx, token, r.resourceType)
				if err != nil {
					if ae, ok := err.(*apiError); !(ok && ae.isBenignUnsupported() && quietBenign()) {
						log.Printf("warn: listServices %s: %v", r.resourceType, err)
					}
					continue
				}
				svcs = c
			}
			servicesCache[r.resourceType] = svcs
		}

		for _, svc := range svcs {
			if isUnsupported(r.resourceType, svc) {
				continue
			}
			var qresp quotaLimitsResp
			params := map[string]string{
				"resource.id":   r.id,
				"resource.type": r.resourceType,
				"service":       svc,
			}
			if err := apiGET(ctx, apiEndpoints["quotaLimits"], token, params, &qresp); err != nil {
				if ae, ok := err.(*apiError); ok && ae.isBenignUnsupported() {
					markUnsupported(r.resourceType, svc)
					if !quietBenign() {
						log.Printf("info: unsupported %s/%s: %s", r.resourceType, svc, ae.Message)
					}
				} else {
					log.Printf("warn: quota limits %s/%s: %v", r.resourceType, svc, err)
				}
				continue
			}

			for _, q := range qresp.QuotaLimits {
				if q.Usage == nil || q.Limit == nil || q.QuotaID == "" {
					continue
				}
				lbls := prometheus.Labels{
					"resource_label_key": r.labelKey,
					"resource_id":        r.id,
					"service":            svc,
					"quota_id":           q.QuotaID,
					"resource_type":      r.resourceType,
					"org_id":             r.orgID,
					"cloud_id":           r.cloudID,
					"org_name":           r.orgName,
					"cloud_name":         r.cloudName,
				}
				quotaUsageGauge.With(lbls).Set(*q.Usage)
				quotaLimitGauge.With(lbls).Set(*q.Limit)
			}
		}
	}

	lastScrapeStatus.Set(1)
	lastScrapeTs.Set(float64(time.Now().Unix()))
	return nil
}

// ================== HTTP server ==================

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		if err := scrapeOnce(ctx); err != nil {
			log.Printf("scrape error: %v", err)
			lastScrapeStatus.Set(0)
		}
		promhttp.Handler().ServeHTTP(w, r)
	}))

	log.Printf("listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}
