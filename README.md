# ECG: Elastic Container Gatherer

ECG is a tool to gather an inventory of images in use by Amazon Elastic
Container Service (ECS).

## Usage

ECG is a command line tool. It can be run with the following command:

```
$ ./ecg --help
ECG (Elastic Container Gatherer) can poll Amazon ECS (Elastic Container Service) APIs to tell Anchore which Images are currently in-use

Usage:
ecg [flags]
ecg [command]

Available Commands:
completion  Generate Completion script
help        Help about any command
version     show the version

Flags:
-c, --config string                     application config file
-h, --help                              help for ecg
-m, --mode string                       execution mode, options=[adhoc periodic] (default "adhoc")
-o, --output string                     report output formatter, options=[json table] (default "json")
-p, --polling-interval-seconds string   If mode is 'periodic', this specifies the interval (default "300")
-r, --region string                     If set overrides the AWS_REGION environment variable/region specified in ECG config
-v, --verbose count                     increase verbosity (-v = info, -vv = debug)

Use "ecg [command] --help" for more information about a command.
```

## Configuration

ECG needs to be configured with AWS credentials and ECG configuration.

### AWS Credentials

ECG uses the AWS SDK for Go. The SDK will look for credentials in the following
order:

1. Environment variables
2. Shared credentials file (~/.aws/credentials)
    ```
    [default]
    aws_access_key_id = <YOUR_ACCESS_KEY_ID>
    aws_secret_access_key = <YOUR_SECRET_ACCESS_KEY>
    ```

### ECG Configuration

ECG can be configured with a configuration file. The default location the configuration
file is looked for is `~/.ecg/config.yaml`. The configuration file can be overridden with
the `-c` flag.

```
# same as -o ; the output format (options: table, json)
output: "json"

log:
  level: "debug"
  # location to write the log file (default is not to have a log file)
  file: "./ecg.log"

anchore:
url: <your anchore api url> (e.g. http://localhost:8228)
  user: <ecg_inventory_user>
  password: $ECG_ANCHORE_PASSWORD
  http:
    insecure: true
    timeout-seconds: 10
```
