# Cert Alert

This app continuously scanns [Certificate Transparency (CT) logs](https://certificate.transparency.dev/) for customizable keywords, regular expressions or wildcard patterns, to get alerted when a certificate for your domain is issued. It can be used, for example, to discover subdomains as well.

It uses [Shoutrrr URLs](https://containrrr.dev/shoutrrr/v0.8/services/overview/) so that you can easily configure the app to use your favourite notification service, or even webhooks / email.

## How to run

The app can be run through Docker, or compiled using Golang.

### Quickstart

You can use the pre-built image from the GitHub Container Registry to get started.

```bash
docker run --name cert-alert -v $PWD/config:/app/config -d ghcr.io/janic0/cert-alert:latest
```

### Cofiguration

Cert-alert is configured thorugh a Yaml file in `config/config.yml` and should look something like the example below.
You can either use Google's list of usable logs or provide a custom list of logs that you maintain on your own. CloudFlare offers a log of [the most popular CT logs](https://ct.cloudflare.com/logs) here:

```yaml
prometheus:
  enabled: true

logCollection:
  logRenewalInterval: 10s
  maxHandleableLogGap: 10000000

  googleLogListURL: https://www.gstatic.com/ct/log_list/v3/log_list.json # automatically use Google's list of usable logs
  logsURLs: # optionally provide (additional) logs to monitor
    - https://oak.ct.letsencrypt.org/2025h2

watchers:
  - glob: "*.workers.dev"
    notifiers:
      - shoutrrrURL: pushover://shoutrrr:apiKey@userId
  - regexp: "[A-Za-z]+.co.uk"
    notifiers:
      - shoutrrrURL: bark://devicekey@host
      - shoutrrrURL: discord://token@id
      - shoutrrrURL: smtp://username:password@host:port/?from=fromAddress&to=recipient1
      - shoutrrrURL: gotify://gotify-host/token
      - shoutrrrURL: generic://example.com
      # See more options here: https://containrrr.dev/shoutrrr/v0.8/services/overview/
```

The configuration is reloaded for every run (every logRenewalInterval).

### Building and running

You can also build the app yourself and run it using Docker, or alternatively compile it to a binary.

```bash
docker build . -t janic0/cert-alert
```

```bash
docker run --name cert-alert -v $PWD/config:/app/config -d janic0/cert-alert
```

```bash
go build . -t cert-alert
```

### Docker Compose

```compose
services:
    cert-alert:
        image: ghcr.io/janic0/cert-alert
        volumes:
            - ./config:/app/config
        restart: unless-stopped
```

### Instrumentation

If you enable Prometheus in the configuration, a HTTP server on port 2112 will serve various metrics.

- certalert_instruction_channel_buffered_items
- certalert_log_certs_ingested_total
- certalert_log_dns_names_ingested_total
- certalert_log_tree_size
- certalert_log_entry_request
- certalert_log_ingest_duration_seconds
- certalert_log_iterations_missed_count
- certalert_log_iterations_skipped_count
- certalert_iteration_count
