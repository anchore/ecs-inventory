# Anchore ECS Inventory

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
`~/.anchore-ecs-inventory.yaml`. The configuration file can be overridden
with the `-c` flag.

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

quiet: false
```

You can also override any configuration value with environment variables. They
must be prefixed with `ANCHORE_ECS_INVENTORY_` and be in all caps. For example,
`ANCHORE_ECS_INVENTORY_LOG_LEVEL=error` would override the `log.level`
configuration

## Releasing
To create a release of `anchore-ecs-inventory`, a tag needs to be created that points to a commit in `main`
that we want to release. This tag shall be a semver prefixed with a `v`, e.g. `v0.2.7`.
Once pushed to origin, this will trigger a GitHub Action that will create the release.

```sh
git tag -s -a v0.2.7 -m "v0.2.7"
git push origin v0.2.7
```

After the release has been successfully created, make sure to specify the updated version
in the `ecs-inventory` Helm Chart in [anchore-charts](https://github.com/anchore/anchore-charts). 
The files to edit are `Chart.yaml` and `values.yaml`.