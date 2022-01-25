# Summary
Recon-Bluster is a automated recon tools based on target domain. Combining a set of the best tools to enumeration endpoint and generate a target endpoint for further vulnerability scanning.
# Installation
```shell
git clone https://github.com/superzerosec/recon-bluster.git
cd recon-bluster
bash install.sh
```
# Usage
```shell
usage: recon-bluster.py [-h] [-d DOMAIN] [-l LIST]

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain
  -l LIST, --list LIST  List of target domain saperated with new line
```

Recon single target on `tesla.com`
```shell
python3 recon-bluster.py -d tesla.com
```
For multiple target in file, create a `list.txt`
```shell
bugcrowd.com
tesla.com
uber.com
```
Recon multiple target on `list.txt`
```shell
python3 recon-bluster.py -l list.txt
```