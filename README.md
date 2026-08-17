# Anchore ECS Inventory

> **Note: this integration requires a valid license or subscription entitlement
> from Anchore**

`anchore-ecs-inventory` is a tool to gather an inventory of images in use by
Amazon Elastic Container Service (ECS).

## Usage

`anchore-ecs-inventory` is a command line tool. It can be run with the following
command:

```
$ anchore-ecs-inventory can poll Amazon ECS (Elastic Container Service) APIs to tell Anchore which Images are currently in-use

Usage:
  anchore-ecs-inventory [flags]
  anchore-ecs-inventory [command]

Available Commands:
  completion  Generate Completion script
  help        Help about any command
  version     show the version

Flags:
  -c, --config string                     application config file
  -d, --dry-run                           do not report inventory to Anchore
  -h, --help                              help for anchore-ecs-inventory
  -p, --polling-interval-seconds string   this specifies the polling interval of the ECS API in seconds (default "300")
  -q, --quiet                             suppresses inventory report output to stdout
  -r, --region string                     if set overrides the AWS_REGION environment variable/region specified in anchore-ecs-inventory config
  -v, --verbose count                     increase verbosity (-v = info, -vv = debug)

Use "anchore-ecs-inventory [command] --help" for more information about a command.
```

## Configuration

`anchore-ecs-inventory` needs to be configured with AWS credentials and Anchore
ECS Inventory configuration.

### AWS Credentials

Anchore ECS Inventory uses the AWS SDK for Go. The SDK will look for credentials
in the following order:

1. Environment variables
2. Shared credentials file (~/.aws/credentials)
   ```
   [default]
   aws_access_key_id = <YOUR_ACCESS_KEY_ID>
   aws_secret_access_key = <YOUR_SECRET_ACCESS_KEY>
   ```

### Anchore ECS Inventory Configuration

Anchore ECS Inventory can be configured with a configuration file. The default
location the configuration file is looked for is
`~/.anchore-ecs-inventory.yaml`. The configuration file can be overridden with
the `-c` flag.

```yaml
log:
  # level of logging that anchore-ecs-inventory will do  { 'error' | 'info' | 'debug }
  level: "info"

  # location to write the log file (default is not to have a log file)
  file: "./anchore-ecs-inventory.log"

anchore:
  # anchore enterprise api url  (e.g. http://localhost:8228)
  url: $ANCHORE_ECS_INVENTORY_ANCHORE_URL

  # anchore enterprise username
  user: $ANCHORE_ECS_INVENTORY_ANCHORE_USER

  # anchore enterprise password
  password: ANCHORE_ECS_INVENTORY_ANCHORE_PASSWORD

  # anchore enterprise account that the inventory will be sent
  account: $ANCHORE_ECS_INVENTORY_ANCHORE_ACCOUNT

  http:
    insecure: true
    timeout-seconds: 10

# the aws region
region: $ANCHORE_ECS_INVENTORY_REGION

# frequency of which to poll the region
polling-interval-seconds: 300

# frequency of which to send health reports to anchore enterprise (30-600)
health-report-interval-seconds: 60

# how this agent identifies itself when registering as an integration with anchore
# enterprise (see "Health reporting" below). anything left empty is derived at runtime.
anchore-registration:
  registration-id: ""
  registration-instance-id: ""
  integration-name: ""
  integration-description: ""

quiet: false
```

You can also override any configuration value with environment variables. They
must be prefixed with `ANCHORE_ECS_INVENTORY_` and be in all caps. For example,
`ANCHORE_ECS_INVENTORY_LOG_LEVEL=error` would override the `log.level`
configuration

### Health reporting

On start-up `anchore-ecs-inventory` registers itself with Anchore Enterprise as an
integration of type `ecs_inventory_agent`, and then reports its health on an interval.
Enterprise uses this to show whether the agent is running and whether its inventory
reports are getting through, per ECS cluster.

Two v2 API endpoints are used, in addition to the inventory endpoint:

| Purpose | Endpoint |
| --- | --- |
| Register | `POST /v2/system/integrations/registration` |
| Health report | `POST /v2/system/integrations/{integration_uuid}/health-report` |

Requirements and behaviour:

- **Anchore Enterprise v6.2.0 or later.** Against an older deployment the agent logs a
  warning and carries on reporting inventory; health reporting stays off. The agent
  never exits for this reason.
- **The configured user needs both the `registerIntegration` and `reportHealth` RBAC
  actions** — `registerIntegration` for the registration endpoint and `reportHealth` for
  the health report endpoint. Missing either is logged clearly and the agent continues
  reporting inventory only.
- **Registration never gates inventory reporting.** Registration retries an unreachable
  Anchore indefinitely, and inventory reporting runs on its normal polling interval
  throughout, exactly as it did before health reporting existed.
- **`--dry-run` neither registers nor sends health reports.**
- A failure that stops the agent collecting anything for its region — expired AWS
  credentials, a revoked `ecs:ListClusters`, a bad region — is reported as an error on
  the health report, which marks the integration unhealthy in Enterprise. Per-cluster
  failures are reported against the cluster they belong to.
- Anchore Enterprise identifies an agent by the **pair**
  (`registration-id`, `registration-instance-id`), and creates a new integration record
  for any pair it has not seen before. Old records are marked inactive rather than
  removed, so both halves need to be stable across restarts — and, because Enterprise
  does not qualify the pair by region or account, unique across every agent reporting
  into the same Enterprise.
- When the agent runs as an ECS task both halves are derived from the ECS task metadata
  endpoint: the task family and the ECS service name respectively, falling back to the
  task family when the task belongs to no service, each qualified with the AWS account
  the agent runs in, the cluster its own task runs in, and the region it is configured
  to scan (for example
  `anchore-ecs-inventory/123456789012/arn:aws:ecs:us-east-1:123456789012:cluster/agents/us-east-1`).
  The family and service name give stability — they survive task replacement, which the
  task id does not, so the task id is deliberately not used — while the account, cluster
  and region give uniqueness, so the same task definition deployed into several regions
  or AWS accounts still registers as several integrations rather than colliding on one.
  The account id is read from the task ARN, which is how two accounts running a
  same-named cluster stay distinct even when the metadata endpoint reports the cluster
  as a bare name rather than an ARN.
- When the agent runs anywhere else, **set both `anchore-registration.registration-id`
  and `anchore-registration.registration-instance-id` to stable values.** Otherwise the
  registration id is generated per run and the instance id falls back to the hostname,
  neither of which is stable in a container, and every restart leaves another
  integration record behind in Enterprise. Both options are also useful in ECS: setting
  the instance id explicitly is how several replicas of the agent within one cluster can
  be told apart. Values given in config are used exactly as configured — they are not
  qualified with the cluster and region — so when you set them, make them unique per
  agent as well as stable.

The agent's configuration is never included in what it registers, so no AWS region or
credential material is sent to Anchore.

## Releasing

To create a release of `anchore-ecs-inventory`, a tag needs to be created that
points to a commit in `main` that we want to release. This tag shall be a semver
prefixed with a `v`, e.g. `v0.2.7`. Once pushed to origin, this will trigger a
GitHub Action that will create the release.

```sh
git tag -s -a v0.2.7 -m "v0.2.7"
git push origin v0.2.7
```

After the release has been successfully created, make sure to specify the
updated version in the `ecs-inventory` Helm Chart in
[anchore-charts](https://github.com/anchore/anchore-charts). The files to edit
are `Chart.yaml` and `values.yaml`.
