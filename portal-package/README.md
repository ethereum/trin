# WARNING
This project is very experimental and prone to bugs of all kinds. If you run into a bug, please create an issue/pr and we'll address it asap.

# What?
A [Kurtosis](https://docs.kurtosis.com/) project for the [Portal Network](https://www.ethportal.net).

# Why?
To easily spin up testnets of portal clients, with all kinds of variations, and test them.

***TO RUN THIS PROJECT YOU NEED PANDAOPS SECRETS & AN INFURA ID***

If you don't know what pandaops secrets are, you probably don't have access to them. But we are working on making this project accessible for everyone to use asap.

# How?
1. Create a `.secrets.json` file in the root directory. These are needed for the bridge to access the data provider.
    ### Example
    ```json
    {
        "PANDAOPS_CLIENT_ID": "xyz",
        "PANDAOPS_CLIENT_SECRET": "abc",
        "TRIN_INFURA_PROJECT_ID": "xxx"
    }
    ```
2. Download [Kurtosis](https://docs.kurtosis.com/install)
3. Start Docker
4. `kurtosis clean -a && kurtosis run --enclave kurtosis-trin .`

# Simple test example...
1. Run kurtosis with the default settings.
2. Fill in the `ports` inside `validate.py` with the ports from the participant services. You can grab these values from the `run`/`inspect` commands.
3. Run `python validate.py` and it will check that the expected data has been gossipped to all participant nodes.

# Useful Commands
When you run kurtosis, it's typical to prepend the `run` command with a `clean` command to ensure that any hanging artifacts / processes from a previous run are removed.

### Run default settings (from root dir)
`kurtosis clean -a && kurtosis run --enclave kurtosis-trin .`

This will create a testnet with one bridge (`mode=single:b1`), one bootnode (trin), and one trin participant.

### Always pull latest images from docker hub
`kurtosis clean -a && kurtosis run --image-download always --enclave kurtosis-trin . "$(cat ./config.yml)"`

### Run custom settings
`kurtosis clean -a && kurtosis run --enclave kurtosis-trin . "$(cat ./config.yml)"`

To create a testnet with custom settings, all you need to do is adjust the `config.yml` file as required. To add a participant/bridge/bootnode service, just add another entry to the respective list. It's not required to explicitly define all fields, fields that are omitted from the `config.yml` will be overwritten with their default value (defined inside `src/utils/input_parser.star`. It is recommended that a `private_key` is included for each service defined inside the config.

### View Glados / Metrics
By default, running this kurtosis package will start a [Glados](https://github.com/ethereum/glados) instance and launch a Grafana dashboard for metrics. To view either of these, just grab the url (for `glados-web` or `grafana`) from the `enclave inspect` command and paste it into your local browser.

### Inspect an enclave
`kurtosis enclave inspect kurtosis-trin`

### View logs from a service
`kurtosis service logs kurtosis-trin {service_name}`

### Open a shell into a service
`kurtosis service shell kurtosis-trin {service_name}`


# Todo
- support fluffy bridge
- support fluffy bootnode
- add ultralight participant / bootnode
- log levels
- anything else? just create an issue for desired features.
