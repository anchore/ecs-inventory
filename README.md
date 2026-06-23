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
  -a, --assume-role-arn string            if set, the ARN of an IAM role to assume (via STS) before querying ECS; may be in the same or a different AWS account
  -e, --external-id string                optional external ID to use when assuming --assume-role-arn (required by some cross-account role trust policies)
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

When running as a daemon in ECS, the recommended approach is to attach an IAM
task role to the task definition rather than supplying static credentials.

#### Required IAM permissions

The identity that queries ECS (the task role, the static credentials, or the
assumed role described below) needs read/list access to ECS. The following
policy grants exactly the API actions `anchore-ecs-inventory` calls:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AnchoreEcsInventoryRead",
      "Effect": "Allow",
      "Action": [
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:ListTasks",
        "ecs:DescribeServices",
        "ecs:DescribeTasks",
        "ecs:ListTagsForResource"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Assuming a role (including cross-account)

Anchore ECS Inventory can assume an IAM role before querying ECS. This is useful
for collecting inventory from an account other than the one the daemon runs in,
and for local testing. Set `assume-role-arn` (and, if the target role's trust
policy requires it, `external-id`):

```yaml
# the ARN of the role to assume before querying ECS. The role may be in the
# same account or a different one, provided its trust policy allows the base
# credentials (env vars, shared credentials, or the ECS task role) to assume it.
assume-role-arn: arn:aws:iam::123456789012:role/anchore-ecs-inventory

# optional - only needed if the target role's trust policy requires an external ID
external-id: ""
```

These can also be set via the `-a`/`--assume-role-arn` and `-e`/`--external-id`
flags, or the `ANCHORE_ECS_INVENTORY_ASSUME_ROLE_ARN` and
`ANCHORE_ECS_INVENTORY_EXTERNAL_ID` environment variables. The assumed
credentials are refreshed automatically as they expire, so this works for the
long-running daemon.

Assuming a role requires permissions on both sides of the trust relationship:

1. **The base identity** (the ECS task role or static credentials the daemon
   starts with) must be allowed to assume the target role:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "AnchoreEcsInventoryAssumeRole",
         "Effect": "Allow",
         "Action": "sts:AssumeRole",
         "Resource": "arn:aws:iam::123456789012:role/anchore-ecs-inventory"
       }
     ]
   }
   ```

2. **The target role** must (a) grant the [ECS read permissions](#required-iam-permissions)
   above, and (b) have a trust policy allowing the base identity to assume it.
   For a cross-account role, the trust policy names the base account/role as the
   principal. Add the `sts:ExternalId` condition only if you set `external-id`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::111111111111:role/anchore-ecs-inventory-task-role"
         },
         "Action": "sts:AssumeRole",
         "Condition": {
           "StringEquals": { "sts:ExternalId": "your-external-id" }
         }
       }
     ]
   }
   ```

   Here `111111111111` is the account the daemon runs in and `123456789012`
   (from `assume-role-arn`) is the account being inventoried. For a same-account
   role the principal simply references a role in the same account.

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

# optional - the ARN of an IAM role to assume (via STS) before querying ECS.
# May be in the same or a different AWS account. Leave empty to use the
# ambient credentials directly.
assume-role-arn: ""

# optional - external ID to use when assuming assume-role-arn (only needed if
# the target role's trust policy requires it)
external-id: ""

# frequency of which to poll the region
polling-interval-seconds: 300

quiet: false
```

You can also override any configuration value with environment variables. They
must be prefixed with `ANCHORE_ECS_INVENTORY_` and be in all caps. For example,
`ANCHORE_ECS_INVENTORY_LOG_LEVEL=error` would override the `log.level`
configuration

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
