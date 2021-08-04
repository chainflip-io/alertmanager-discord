package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	golog "log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/alertmanager/template"
)

// Discord color values
const (
	ColorRed   = 0x992D22
	ColorGreen = 0x2ECC71
	ColorGrey  = 0x95A5A6
)

type alertManAlert struct {
	Annotations struct {
		Description string `json:"description"`
		Summary     string `json:"summary"`
		RunbookUrl  string `json:"runbook_url"`
	} `json:"annotations"`
	EndsAt       string            `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Labels       map[string]string `json:"labels"`
	StartsAt     string            `json:"startsAt"`
	Status       string            `json:"status"`
}

type alertManOut struct {
	Alerts            []alertManAlert `json:"alerts"`
	CommonAnnotations struct {
		Summary string `json:"summary"`
	} `json:"commonAnnotations"`
	CommonLabels struct {
		Alertname string `json:"alertname"`
	} `json:"commonLabels"`
	ExternalURL string `json:"externalURL"`
	GroupKey    string `json:"groupKey"`
	GroupLabels struct {
		Alertname string `json:"alertname"`
	} `json:"groupLabels"`
	Receiver string `json:"receiver"`
	Status   string `json:"status"`
	Version  string `json:"version"`
}

type discordOut struct {
	Content string         `json:"content"`
	Embeds  []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []discordEmbedField `json:"fields"`
}

type discordEmbedField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

const defaultListenAddress = "127.0.0.1:9094"

var (
	whURL          = flag.String("webhook.url", os.Getenv("DISCORD_WEBHOOK"), "Discord WebHook URL.")
	listenAddress  = flag.String("listen.address", os.Getenv("LISTEN_ADDRESS"), "Address:Port to listen on.")
	runbookBaseURL = flag.String("runbook.url", os.Getenv("RUNBOOK_URL"), "BaseURL to runbooks")
)

func checkWhURL(whURL string, runbookBaseUrl string) {
	if whURL == "" {
		golog.Fatalf("Environment variable 'DISCORD_WEBHOOK' or CLI parameter 'webhook.url' not found.")
	}
	if runbookBaseUrl == "" {
		golog.Printf("Environment variable 'RUNBOOK_URL' or CLI parameter 'runbook.url' not found. Continuing without...")
	}
	_, err := url.Parse(whURL)
	if err != nil {
		golog.Fatalf("The Discord WebHook URL doesn't seem to be a valid URL.")
	}

	re := regexp.MustCompile(`https://discord(?:app)?.com/api/webhooks/[0-9]{18}/[a-zA-Z0-9_-]+`)
	if ok := re.Match([]byte(whURL)); !ok {
		golog.Printf("The Discord WebHook URL doesn't seem to be valid.")
	}
}

func sendWebhook(amo *alertManOut) {
	groupedAlerts := make(map[string][]alertManAlert)

	for _, alert := range amo.Alerts {
		groupedAlerts[alert.Status] = append(groupedAlerts[alert.Status], alert)
	}

	for status, alerts := range groupedAlerts {
		DO := discordOut{}

		RichEmbed := discordEmbed{
			Title:       fmt.Sprintf("[%s:%d] %s", strings.ToUpper(status), len(alerts), amo.CommonLabels.Alertname),
			Description: amo.CommonAnnotations.Summary,
			Color:       ColorGrey,
			Fields:      []discordEmbedField{},
		}

		if status == "firing" {
			RichEmbed.Color = ColorRed
		} else if status == "resolved" {
			RichEmbed.Color = ColorGreen
		}

		if amo.CommonAnnotations.Summary != "" {
			DO.Content = fmt.Sprintf(" === %s === \n", amo.CommonAnnotations.Summary)
		}

		for _, alert := range alerts {
			realname := alert.Labels["instance"]
			if strings.Contains(realname, "localhost") && alert.Labels["exported_instance"] != "" {
				realname = alert.Labels["exported_instance"]
			}

			RichEmbed.Fields = append(RichEmbed.Fields, discordEmbedField{
				Name:  fmt.Sprintf("[%s]: %s on %s", strings.ToUpper(status), alert.Labels["alertname"], realname),
				Value: alert.Annotations.Description,
			})

			baseUrl := *runbookBaseURL
			severity := alert.Labels["severity"]
			code := alert.Labels["code"]
			if baseUrl != "" && severity != "" && code != "" {
				runbookUrl := baseUrl + path.Join(severity, code)
				discordLink := fmt.Sprintf("[Click here for Runbook](%s.md)", runbookUrl)
				RichEmbed.Fields = append(RichEmbed.Fields, discordEmbedField{
					Name:  "Runbook URL",
					Value: discordLink,
				})
			}
		}

		DO.Embeds = []discordEmbed{RichEmbed}

		DOD, _ := json.Marshal(DO)
		_, err := http.Post(*whURL, "application/json", bytes.NewReader(DOD))
		if err != nil {
			fmt.Println(err)
		}
	}
}

func sendRawPromAlertWarn() {
	badString := `This program is suppose to be fed by alertmanager.` + "\n" +
		`It is not a replacement for alertmanager, it is a ` + "\n" +
		`webhook target for it. Please read the README.md  ` + "\n" +
		`for guidance on how to configure it for alertmanager` + "\n" +
		`or https://prometheus.io/docs/alerting/latest/configuration/#webhook_config`

	golog.Print(`/!\ -- You have misconfigured this software -- /!\`)
	golog.Print(`--- --                                      -- ---`)
	golog.Print(badString)

	DO := discordOut{
		Content: "",
		Embeds: []discordEmbed{
			{
				Title:       "You have misconfigured this software",
				Description: badString,
				Color:       ColorGrey,
				Fields:      []discordEmbedField{},
			},
		},
	}

	DOD, _ := json.Marshal(DO)
	http.Post(*whURL, "application/json", bytes.NewReader(DOD))
}

func logAlerts(alerts template.Data, logger log.Logger) error {
	logger = logWith(alerts.CommonAnnotations, logger)
	logger = logWith(alerts.CommonLabels, logger)
	logger = logWith(alerts.GroupLabels, logger)
	for _, alert := range alerts.Alerts {
		alertLogger := logWith(alert.Labels, logger)
		alertLogger = logWith(alert.Annotations, alertLogger)

		err := alertLogger.Log("status", alert.Status, "startsAt", alert.StartsAt, "endsAt", alert.EndsAt, "generatorURL", alert.GeneratorURL, "externalURL", alerts.ExternalURL, "receiver", alerts.Receiver)
		if err != nil {
			return err
		}
	}

	return nil
}

func logWith(values map[string]string, logger log.Logger) log.Logger {
	for k, v := range values {
		logger = log.With(logger, k, v)
	}
	return logger
}

func main() {
	flag.Parse()
	checkWhURL(*whURL, *runbookBaseURL)

	if *listenAddress == "" {
		*listenAddress = defaultListenAddress
	}

	var logger log.Logger
	lw := log.NewSyncWriter(os.Stdout)
	logger = log.NewJSONLogger(lw)

	golog.Printf("Listening on: %s", *listenAddress)
	golog.Fatalf("Failed to listen on HTTP: %v",
		http.ListenAndServe(*listenAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			golog.Printf("%s - [%s] %s", r.Host, r.Method, r.URL.RawPath)

			b, err := ioutil.ReadAll(r.Body)
			if err != nil {
				panic(err)
			}

			amo := alertManOut{}
			aml := template.Data{}
			err = json.Unmarshal(b, &amo)
			err = json.Unmarshal(b, &aml)
			if err != nil {
				if isRawPromAlert(b) {
					sendRawPromAlertWarn()
					return
				}

				if len(b) > 1024 {
					golog.Printf("Failed to unpack inbound alert request - %s...", string(b[:1023]))

				} else {
					golog.Printf("Failed to unpack inbound alert request - %s", string(b))
				}

				return
			}

			logAlerts(aml, logger)
			sendWebhook(&amo)
		})))
}
