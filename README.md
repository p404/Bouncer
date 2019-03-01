# Bouncer

Bouncer is a a AWS security group updater, based on github web-hooks CIDRs.

## Installing
```bash
1. git clone https://github.com/p404/Bouncer.git
2. cd Bouncer
3. pip install -r requirements.txt 
```
## How to use
```bash
usage: bouncer.py [-h] -c CONFIG

Bouncer is a a AWS security group updater, based on github web-hooks CIDRs.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Loads configuration
```
## Configuration example
config.ini
```bash
[global]
vault_server      = <VAULT SERVER>
vault_token       = <VAULT TOKEN>
vault_secret_path = <VAULT SECRET PATH>
```
## License
[MIT](https://github.com/p404/Bouncer/blob/master/LICENSE)