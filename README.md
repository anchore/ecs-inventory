# Anchore ECS Inventory

`anchore-ecs-inventory` is a tool to gather an inventory of images in use by Amazon Elastic
Container Service (ECS).

## Usage

`anchore-ecs-inventory` is a command line tool. It can be run with the following command:

```
$ ./anchore-ecs-inventory --help
ECG (Elastic Container Gatherer) can poll Amazon ECS (Elastic Container Service) APIs to tell Anchore which Images are currently in-use

Usage:
anchore-ecs-inventory [flags]
anchore-ecs-inventory [command]

Available Commands:
completion  Generate Completion script
help        Help about any command
version     show the version

Flags:
-c, --config string                     application config file
-h, --help                              help for anchore-ecs-inventory
-p, --polling-interval-seconds string   This specifies the polling interval of the ECS API in seconds (default "300")
-q, --quiet                             Suppresses inventory report output to stdout
-r, --region string                     If set overrides the AWS_REGION environment variable/region specified in ECG config
-v, --verbose count                     increase verbosity (-v = info, -vv = debug)

Use "anchore-ecs-inventory [command] --help" for more information about a command.
```

## Configuration

`anchore-ecs-inventory` needs to be configured with AWS credentials and Anchore ECS Inventory configuration.

### AWS Credentials

Anchore ECS Inventory uses the AWS SDK for Go. The SDK will look for credentials in the following
order:

1. Environment variables
2. Shared credentials file (~/.aws/credentials)
    ```
    [default]
    aws_access_key_id = <YOUR_ACCESS_KEY_ID>
    aws_secret_access_key = <YOUR_SECRET_ACCESS_KEY>
    ```

### Anchore ECS Inventory Configuration

Anchore ECS Inventory can be configured with a configuration file. The default location the configuration
file is looked for is `~/.anchore-ecs-inventory/config.yaml`. The configuration file can be overridden with
the `-c` flag.

```
log:
  level: "debug"
  # location to write the log file (default is not to have a log file)
  file: "./anchore-ecs-inventory.log"

anchore:
  url: <your anchore api url> (e.g. http://localhost:8228)
  user: <anchore-ecs-inventory_inventory_user>
  password: $ECG_ANCHORE_PASSWORD
  http:
    insecure: true
    timeout-seconds: 10

quiet: false
```
