# Deployment Guide — 3-Agent Incident Response System

This guide describes four deployment shapes, ordered from simplest to most
production-grade. Pick the one that matches your operating model.

| # | Shape | Best for | Trigger |
|---|-------|----------|---------|
| 1 | systemd timer / cron on a Linux management host | Small ops teams, on-prem, single-tenant | Scheduled (every N minutes) or oncall manual |
| 2 | AWS Lambda + S3 event | AWS-native shops who already ship logs to S3 | Real-time, on log upload |
| 3 | Google Cloud Function + GCS event | GCP-native shops | Real-time, on log upload |
| 4 | Kubernetes CronJob (or KEDA-triggered Job) | Teams already running on K8s alongside the API | Scheduled or event-driven |

All four shapes share the same secret-management story: pull `GEMINI_API_KEY`
from a managed secret store (never bake it into the image or env file). Remove
the hard-coded fallback in `agents.py` before any non-evaluation deployment.

---

## 0. Pre-deployment hardening (do this once, regardless of shape)

1. **Strip the evaluation default for `GEMINI_API_KEY`** in `agents.py`:
   ```python
   GEMINI_API_KEY = os.environ["GEMINI_API_KEY"]   # fail fast, no default
   ```
2. **Pin dependencies.** Add a `requirements.txt`:
   ```
   pydantic>=2,<3
   google-generativeai>=0.7
   duckduckgo-search>=6        # optional
   ```
3. **Lint the curated docs map.** Add a CI step that does a `HEAD` request
   against every URL in `agents.KNOWN_DOCS` and fails the build on 4xx/5xx.
4. **Enable structured logging.** Wrap orchestrator output in JSON lines so
   downstream pipelines (CloudWatch, Cloud Logging, Loki) can parse it.
5. **Containerize.** A minimal `Dockerfile`:
   ```dockerfile
   FROM python:3.12-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY agents.py main.py log_generator.py ./
   ENTRYPOINT ["python", "main.py"]
   ```

---

## 1. systemd timer on a Linux management host

The simplest production-shaped deployment: a small EC2 / VM that has read
access to the API host's `/var/log/` (via `rsync`, `scp`, or a shared NFS
mount) and outbound HTTPS to `generativelanguage.googleapis.com`.

### 1a. Install

```bash
sudo useradd --system --home /opt/incident-response --shell /usr/sbin/nologin ir-agent
sudo mkdir -p /opt/incident-response /var/log/ir-agent /etc/ir-agent
sudo chown -R ir-agent:ir-agent /opt/incident-response /var/log/ir-agent

# Copy the project
sudo -u ir-agent git clone <your-repo> /opt/incident-response
cd /opt/incident-response
sudo -u ir-agent python3 -m venv .venv
sudo -u ir-agent .venv/bin/pip install -r requirements.txt
```

### 1b. Secret

```bash
# Use a root-owned, mode-0600 env file the systemd unit can read.
echo "GEMINI_API_KEY=<your-key>" | sudo tee /etc/ir-agent/env >/dev/null
sudo chmod 600 /etc/ir-agent/env
```

For a stronger story, replace this with `systemd-creds` or a sidecar that
hydrates the env from Vault.

### 1c. Service unit — `/etc/systemd/system/ir-agent.service`

```ini
[Unit]
Description=3-Agent Incident Response — single run
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=ir-agent
WorkingDirectory=/opt/incident-response
EnvironmentFile=/etc/ir-agent/env
ExecStart=/opt/incident-response/.venv/bin/python main.py \
    --logs /var/log/api \
    --incident-id INC-%i \
    --out /var/log/ir-agent/report-%i.txt
StandardOutput=append:/var/log/ir-agent/orchestrator.log
StandardError=append:/var/log/ir-agent/orchestrator.log
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/ir-agent
```

### 1d. Timer unit — `/etc/systemd/system/ir-agent.timer`

```ini
[Unit]
Description=Run incident-response agent every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=ir-agent.service

[Install]
WantedBy=timers.target
```

### 1e. Activate

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ir-agent.timer
sudo systemctl list-timers ir-agent.timer
journalctl -u ir-agent.service -f
```

### 1f. Cron alternative

If you don't have systemd, a `cron` line (in `/etc/cron.d/ir-agent`) works:

```cron
*/5 * * * * ir-agent /opt/incident-response/.venv/bin/python /opt/incident-response/main.py --logs /var/log/api --out /var/log/ir-agent/report-$(date +\%s).txt 2>>/var/log/ir-agent/orchestrator.log
```

Source `GEMINI_API_KEY` from a root-owned env file using `BASH_ENV` or by
sourcing it inside a wrapper script — never put the key in the cron line.

---

## 2. AWS Lambda + S3 event (real-time on log upload)

Triggers the pipeline whenever a new bundle of logs lands in S3 — useful when
the API itself ships logs via Firehose / FluentBit / Vector.

### 2a. Architecture

```
   API host (FluentBit) ──► S3://logs-bucket/incidents/{incident-id}/{access,error,app}.log
                                                                │
                                                          (S3 PUT event)
                                                                │
                                                                ▼
                                                  Lambda (this project)
                                                                │
                                                                ▼
                                       SNS / Slack / PagerDuty (the playbook)
```

### 2b. Lambda handler — add to the project as `lambda_handler.py`

```python
import json
import os
import boto3
import urllib.parse

from agents import IncidentInput
from main import Orchestrator, render_playbook

s3 = boto3.client("s3")
sns = boto3.client("sns")
TOPIC_ARN = os.environ["INCIDENT_TOPIC_ARN"]

def handler(event, context):
    # Triggered by an S3 PUT to {prefix}/{incident-id}/<file>
    record = event["Records"][0]["s3"]
    bucket = record["bucket"]["name"]
    key    = urllib.parse.unquote_plus(record["object"]["key"])
    incident_id = key.split("/")[-2]
    prefix = "/".join(key.split("/")[:-1])

    def _read(name):
        return s3.get_object(Bucket=bucket, Key=f"{prefix}/{name}")["Body"].read().decode()

    incident = IncidentInput(
        incident_id=incident_id,
        nginx_access_log=_read("nginx-access.log"),
        nginx_error_log=_read("nginx-error.log"),
        app_error_log=_read("app-error.log"),
        affected_endpoints=[],
    )

    diag, bundle, pb = Orchestrator(use_web=False).run(incident)
    report = render_playbook(diag, bundle, pb)

    # 1) persist the report alongside the logs
    s3.put_object(Bucket=bucket, Key=f"{prefix}/report.txt",
                  Body=report.encode(), ContentType="text/plain")

    # 2) notify oncall
    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[{pb.severity}] {incident_id} — {pb.title[:80]}",
        Message=report,
    )
    return {"ok": True, "report_key": f"{prefix}/report.txt"}
```

### 2c. Packaging

```bash
pip install -t build/ pydantic google-generativeai
cp agents.py main.py log_generator.py lambda_handler.py build/
( cd build && zip -r ../ir-agent.zip . )
```

`google-generativeai` exceeds the 50 MB direct upload limit — upload the zip
to S3 and point the Lambda at it, or use a container image.

### 2d. Configuration (Terraform sketch)

```hcl
resource "aws_lambda_function" "ir_agent" {
  function_name = "ir-agent"
  role          = aws_iam_role.ir_agent.arn
  package_type  = "Image"
  image_uri     = "${aws_ecr_repository.ir.repository_url}:latest"
  timeout       = 120
  memory_size   = 1024
  environment {
    variables = {
      INCIDENT_TOPIC_ARN = aws_sns_topic.incidents.arn
    }
  }
}

# Pull the API key from Secrets Manager at cold-start, not from env vars.
# (Easiest pattern: read it in agents.py via a one-shot boto3 secretsmanager call.)
```

IAM policy must allow `secretsmanager:GetSecretValue` for the Gemini key,
`s3:GetObject`/`s3:PutObject` for the log bucket, and `sns:Publish` for the
notification topic.

S3 bucket notification:

```hcl
resource "aws_s3_bucket_notification" "trigger" {
  bucket = aws_s3_bucket.logs.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.ir_agent.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "incidents/"
    filter_suffix       = "app-error.log"   # only trigger once per incident
  }
}
```

---

## 3. Google Cloud Function + GCS event

Same shape, GCP-flavored. The `agents.py` and `main.py` files are unchanged.

### 3a. Handler — `gcf_main.py`

```python
import os
from google.cloud import storage, secretmanager, pubsub_v1

from agents import IncidentInput
from main import Orchestrator, render_playbook

# Hydrate the API key from Secret Manager at cold start
def _load_secret(name: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    project = os.environ["GCP_PROJECT"]
    version = client.access_secret_version(name=f"projects/{project}/secrets/{name}/versions/latest")
    return version.payload.data.decode()

os.environ["GEMINI_API_KEY"] = _load_secret("gemini-api-key")

storage_client = storage.Client()
publisher = pubsub_v1.PublisherClient()
TOPIC = os.environ["INCIDENT_TOPIC"]   # projects/<p>/topics/incidents

def handler(event, context):
    # GCS object-finalize event
    bucket_name = event["bucket"]
    name = event["name"]                # incidents/<incident-id>/<file>
    if not name.endswith("app-error.log"):
        return  # only trigger once per incident
    prefix = "/".join(name.split("/")[:-1])
    incident_id = prefix.split("/")[-1]

    bucket = storage_client.bucket(bucket_name)
    def _read(fname):
        return bucket.blob(f"{prefix}/{fname}").download_as_text()

    incident = IncidentInput(
        incident_id=incident_id,
        nginx_access_log=_read("nginx-access.log"),
        nginx_error_log=_read("nginx-error.log"),
        app_error_log=_read("app-error.log"),
        affected_endpoints=[],
    )
    diag, bundle, pb = Orchestrator(use_web=False).run(incident)
    report = render_playbook(diag, bundle, pb)

    bucket.blob(f"{prefix}/report.txt").upload_from_string(report, content_type="text/plain")
    publisher.publish(TOPIC, report.encode(),
                      severity=pb.severity, incident_id=incident_id).result()
```

### 3b. Deploy

```bash
gcloud functions deploy ir-agent \
    --gen2 --runtime python312 --region us-central1 \
    --source . --entry-point handler \
    --trigger-event-filters="type=google.cloud.storage.object.v1.finalized" \
    --trigger-event-filters="bucket=YOUR_LOGS_BUCKET" \
    --set-env-vars=GCP_PROJECT=YOUR_PROJECT,INCIDENT_TOPIC=projects/YOUR_PROJECT/topics/incidents \
    --memory=1Gi --timeout=120s
```

Grant the function's service account `roles/secretmanager.secretAccessor`
on the `gemini-api-key` secret, `roles/storage.objectViewer` on the log
bucket, and `roles/pubsub.publisher` on the incidents topic.

---

## 4. Kubernetes CronJob (or KEDA-triggered Job)

The right shape if your API already runs in K8s and ships logs to a shared
volume / ELK / Loki.

### 4a. Secret

```bash
kubectl create secret generic ir-agent-secrets \
    --from-literal=GEMINI_API_KEY="<your-key>"
```

For production, prefer External Secrets + a Vault / Secrets Manager / GSM
backend.

### 4b. CronJob — `k8s/ir-agent-cronjob.yaml`

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ir-agent
spec:
  schedule: "*/5 * * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 5
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          serviceAccountName: ir-agent
          containers:
            - name: ir-agent
              image: registry.example.com/ir-agent:1.0.0
              args:
                - "--logs=/var/log/api"
                - "--out=/reports/report-$(POD_NAME).txt"
              env:
                - name: GEMINI_API_KEY
                  valueFrom:
                    secretKeyRef:
                      name: ir-agent-secrets
                      key: GEMINI_API_KEY
                - name: POD_NAME
                  valueFrom: { fieldRef: { fieldPath: metadata.name } }
              resources:
                requests: { cpu: 100m, memory: 256Mi }
                limits:   { cpu: 500m, memory: 1Gi }
              volumeMounts:
                - { name: api-logs, mountPath: /var/log/api, readOnly: true }
                - { name: reports,  mountPath: /reports }
              securityContext:
                runAsNonRoot: true
                runAsUser: 1000
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities: { drop: ["ALL"] }
          volumes:
            - name: api-logs
              persistentVolumeClaim: { claimName: api-logs-shared }
            - name: reports
              persistentVolumeClaim: { claimName: ir-agent-reports }
```

### 4c. Event-driven variant

To make the Job fire when a new log batch is ready instead of on a schedule,
swap the `CronJob` for a `Job` template managed by a KEDA `ScaledJob` with a
queue trigger (RabbitMQ, SQS, Pub/Sub, Kafka). The handler stays identical.

### 4d. Reporting sink

For all K8s deployments you'll want the report to leave the cluster. Options:

- A sidecar that ships `/reports` to S3/GCS and emits a Slack webhook.
- A small `notify.sh` step appended to `args:` that POSTs the report to
  PagerDuty / Slack / Microsoft Teams.

---

## 5. Operational concerns common to all shapes

- **Cost control.** Each pipeline run makes 2 Gemini calls (Agent 1 +
  Agent 3). With Flash pricing this is cheap, but cap aggressively:
  per-incident token budget, daily call quota, circuit breaker that demotes
  to deterministic output after N consecutive errors.
- **Idempotency.** Use the `incident_id` as a deduplication key on the
  notification side. The same incident should not page oncall five times.
- **Network egress allowlist.** Open only:
  `generativelanguage.googleapis.com:443` (Gemini) and, if Agent 2's web
  augmentation is enabled, `duckduckgo.com:443`.
- **Audit trail.** Persist the full prompt, response, validated Pydantic
  model, latency, and token cost for every Gemini call to your audit store
  (e.g. CloudWatch Logs / Cloud Logging / OpenSearch). Scrub PII from log
  excerpts before persisting.
- **Disaster mode.** When Gemini is unreachable, the deterministic fallback
  must be exercised regularly so it does not bit-rot. Add a monthly canary
  that runs the pipeline with `GEMINI_API_KEY` deliberately blanked and
  asserts on the rendered report shape.
- **Zero-trust on log content.** Treat all log strings as untrusted input.
  The wrapper that builds the `IncidentInput` should strip ANSI escape
  sequences and cap each log file at a sane byte budget before handoff.

---

## 6. Recommended starting point

For most teams: **shape #4 (Kubernetes CronJob)** when the API already runs
on K8s, otherwise **shape #2 (AWS Lambda + S3)** if you're AWS-native and
already shipping logs to S3. Shape #1 is appropriate for small on-prem
deployments and is the easiest to reason about, but doesn't scale to many
APIs without orchestration.
