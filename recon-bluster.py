#!/usr/bin/env python3

import subprocess, os, argparse, sys
from pwn import *
from termcolor import colored

## initialse
version = 0.2
subdomains_output = "subdomains.txt"
new_subdomains_output = "subdomains_new.txt"
intel_domains_output = "intel_domains.txt"
new_intel_domains_output = "intel_domains_new.txt"
tmp_output = "tmp_output.txt"
tmp_input = "tmp_input.txt"
httpx_output = "subdomains_httpx.txt"
waybackurls_output = "subdomains_waybackurls.txt"
gf_sqli_output = "subdomains_gf_sqli.txt"
gf_xss_output = "subdomains_gf_xss.txt"
gf_ssrf_output = "subdomains_gf_ssrf.txt"
gf_upload_fields_output = "subdomains_gf_upload_fields.txt"
contacts_output = "contacts.txt"

def banner():
    print(colored("recon-bluster version {}" .format(version), "green", attrs=['bold']))

def passive_subdomain_enum(args):

    ## assetfinder
    recon = log.progress("Executing assetfinder")
    recon.status('In progress...')
    subprocess.call("assetfinder -subs-only {} | anew {} > {}" .format(args.domain, subdomains_output, new_subdomains_output), shell=True)
    recon.success("Done")

    ## subfinder
    recon = log.progress("Executing subfinder")
    recon.status('In progress...')
    subprocess.call("subfinder -silent -d {} | anew {} >> {}" .format(args.domain, subdomains_output, new_subdomains_output), shell=True)
    recon.success("Done")

    ## crt.sh
    recon = log.progress("Executing crt.sh")
    recon.status('In progress...')
    subprocess.call("curl -s 'https://crt.sh/?q=%25.{}&output=json' | jq -r '.[].name_value' | anew {} >> {}" .format(args.domain, subdomains_output, new_subdomains_output), shell=True)
    recon.success("Done")

    ## amass enum
    recon = log.progress("Executing amass enum")
    recon.status('In progress...')
    subprocess.call("amass enum -silent -passive -d {} | anew {} >> {}" .format(args.domain, subdomains_output, new_subdomains_output), shell=True)
    recon.success("Done")

def intel_domain_enum(args):

    ## amass intel
    recon = log.progress("Executing amass intel")
    recon.status('In progress...')
    subprocess.call("amass intel -whois -d {} | anew {} > {}" .format(args.domain, intel_domains_output, new_intel_domains_output), shell=True)
    recon.success("Done")

def generate_target_file(args):

    ## httpx
    recon = log.progress("Executing httpx")
    recon.status('In progress...')
    subprocess.call("httpx -l {} -ports 80,443,8009,8080,8081,8090,8180,8443 -timeout 10 -threads 200 --follow-redirects -silent | anew {} > {}" .format(new_subdomains_output, httpx_output, tmp_output), shell=True)
    recon.success("Done")

    ## waybackurls
    recon = log.progress("Executing waybackurls")
    recon.status('In progress...')
    subprocess.call("mv {0} {1}; cat {1} | waybackurls | anew {2} > {0}" .format(tmp_output, tmp_input, waybackurls_output), shell=True)
    recon.success("Done")
    
    ## gf sqli
    recon = log.progress("Executing gf sqli")
    recon.status('In progress...')
    subprocess.call("mv {0} {1}; cat {1} | gf sqli | unew -combine | anew {2} >/dev/null 2>&1" .format(tmp_output, tmp_input, gf_sqli_output), shell=True)
    recon.success("Done")

    ## gf xss
    recon = log.progress("Executing gf xxs")
    recon.status('In progress...')
    subprocess.call("cat {} | gf xss | unew -combine | anew {} >/dev/null 2>&1" .format(tmp_input, gf_xss_output), shell=True)
    recon.success("Done")

    ## gf ssrf
    recon = log.progress("Executing gf ssrf")
    recon.status('In progress...')
    subprocess.call("cat {} | gf ssrf | unew -combine | anew {} >/dev/null 2>&1" .format(tmp_input, gf_ssrf_output), shell=True)
    recon.success("Done")

    ## gf upload-fields
    recon = log.progress("Executing gf upload-fields")
    recon.status('In progress...')
    subprocess.call("cat {} | gf upload-fields | anew {} >/dev/null 2>&1" .format(tmp_input, gf_upload_fields_output, tmp_output), shell=True)
    recon.success("Done")

def clean_result():
    
    ## cleaning result
    recon = log.progress("Cleaning result")
    recon.status('In progress...')
    subprocess.call("rm tmp*.txt", shell=True)
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
    print(colored("Passive subdomain enumeration", 'yellow', attrs=['bold']))
    print(colored("--------------------------------------------", 'yellow', attrs=['bold']))
    passive_subdomain_enum(args)
    
    print(colored("\n--------------------------------------------", 'yellow', attrs=['bold']))
    print(colored("Intelligence domain enumeration", 'yellow', attrs=['bold']))
    print(colored("--------------------------------------------", 'yellow', attrs=['bold']))
    intel_domain_enum(args)

    print(colored("\n--------------------------------------------", 'yellow', attrs=['bold']))
    print(colored("Generating target file", 'yellow', attrs=['bold']))
    print(colored("--------------------------------------------", 'yellow', attrs=['bold']))
    generate_target_file(args)

    ## cleaning result
    clean_result()

    print(colored("\n--------------------------------------------", 'green', attrs=['bold']))
    print(colored("Summary", 'green', attrs=['bold']))
    print(colored("--------------------------------------------", 'green', attrs=['bold']))
    summary()

