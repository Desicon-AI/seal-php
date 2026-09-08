# Seal PHP SDK alignment candidate

`Client::init` supports `apiKey`, `signingSecret`, `appName`, `environment`, `endpoint`, `sandbox`, and `waf`. Telemetry uses X-API-Key and optional fresh HMAC signatures. TLS peer and hostname verification are required; configure your host CA certificates instead of disabling verification.

Configure an independent scheduler every minute: Laravel `php artisan seal:heartbeat`, or a cron script that initializes the client and calls `Client::sendCronHeartbeat()`. The command now returns failure if delivery is not acknowledged. Requests to a quiet website are not a reliable heartbeat and no longer trigger liveness checks. Monitor the scheduler itself.

Laravel accepts `SEAL_SIGNING_SECRET` or `seal.signing_secret` and `seal.endpoint`. Deployment reporting uses `/ingest/deployment`; only sandbox errors use `/sandbox/ingest`.

WAF defaults to report. Scanner matching excludes curl, wget and Python requests. SQL/XSS findings obey explicit `waf.sqli.action` / `waf.xss.action`; a normal keyword in an API route does not trigger a blanket denial. Forwarded identity/country headers require `waf.trustProxyHeaders` behind a proxy that sanitizes them. Threat URLs are hashed. This SDK does not execute rescue patches.

Delivery uses synchronous cURL with a two-second timeout; it does add latency when a report is sent. It must not be described as zero latency. Run `php -l src/Client.php` and `php tests/contract.php`; GitHub Actions runs both.

## Optional enforcement rules

The `honeypot`, `sqli`, and `xss` rules accept an `action` of `drop` or `report`. They default to `report`: upgrading does not silently block new classes of traffic. Enable each rule after testing legitimate application workflows. `drop` rejects matching requests and records `action: blocked`; observation mode records `observed`. Honeypot paths include WordPress login/admin paths and must not be blocked on sites that legitimately use those paths. Historical records are not reclassified.
