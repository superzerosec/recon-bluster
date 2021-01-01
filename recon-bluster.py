#!/usr/bin/env python3

import subprocess, os, argparse, sys
from pwn import *
from termcolor import colored

## initialse
version = 0.1
subdomains_output = "subdomains.txt"
tmp_output = "tmp.txt"
contacts_output = "contacts.txt"

def banner():
    print(colored("recon-bluster version {}" .format(version), "green", attrs=['bold']))

def subdomain_enum(args):

    ## assetfinder
    recon = log.progress("Executing assetfinder")
    recon.status('In progress...')
    subprocess.call("assetfinder -subs-only {} >> {}" .format(args.domain, subdomains_output), shell=True)
    recon.success("Done")

    ## subfinder
    recon = log.progress("Executing subfinder")
    recon.status('In progress...')
    subprocess.call("subfinder -silent -d {} >> {}" .format(args.domain, subdomains_output), shell=True)
    recon.success("Done")

    ## crt.sh
    recon = log.progress("Executing crt.sh")
    recon.status('In progress...')
    subprocess.call("curl -s 'https://crt.sh/?q=%25.{}&output=json' | jq -r '.[].name_value' >> {}" .format(args.domain, subdomains_output), shell=True)
    recon.success("Done")

    ## amass enum
    recon = log.progress("Executing amass enum")
    recon.status('In progress...')
    subprocess.call("amass enum -silent -passive -d {0} -o {2}; cat {2} >> {1}" .format(args.domain, subdomains_output, tmp_output), shell=True)
    recon.success("Done")

    ## cleaning result by removing duplicated, email, keyword
    recon = log.progress("Cleaning result")
    recon.status('In progress...')
    subprocess.call("sed 's/[A-Z]/\L&/g' {1} | sort -u > {0}; mv {0} {1}" .format(tmp_output, subdomains_output), shell=True)
    subprocess.call("grep '@' {1} >> {2}; grep -vE '@|\*|cpanel\.|cpcalendars\.|cpcontacts\.|webmail\.|webdisk\.' {1} > {0}; mv {0} {1}; sort -u {2} > {0}; mv {0} {2}" .format(tmp_output, subdomains_output, contacts_output), shell=True)
    #subprocess.call("grep '@' {1} >> {2}; grep -vE '@|\*' {1} > {0}; mv {0} {1}" .format(tmp_output, subdomains_output, contacts_output), shell=True)
    recon.success("Done")

def summary():
    subprocess.call("wc -l *.txt", shell=True)

if __name__ == "__main__":

    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", action="store", help="Target domain", required=True)

    args = parser.parse_args()
    if len(sys.argv[1:])==0:
        parser.print_help()
        parser.exit()

    print(colored("\n--------------------------------------------", 'yellow', attrs=['bold']))
    print(colored("Passive subdomains enumeration", 'yellow', attrs=['bold']))
    print(colored("--------------------------------------------", 'yellow', attrs=['bold']))
    subdomain_enum(args)

    print(colored("\n--------------------------------------------", 'green', attrs=['bold']))
    print(colored("Summary", 'green', attrs=['bold']))
    print(colored("--------------------------------------------", 'green', attrs=['bold']))
    summary()

