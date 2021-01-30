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
tmp_httpx_output = "tmp_httpx_output.txt"
tmp_urls_output = "tmp_urls_output.txt"
tmp_output = "tmp_output.txt"
httpx_output = "subdomains_httpx.txt"
urls_output = "subdomains_urls.txt"
gf_sqli_output = "target_sqli.txt"
gf_xss_output = "target_xss.txt"
gf_ssrf_output = "target_ssrf.txt"
gf_upload_fields_output = "target_upload_fields.txt"
contacts_output = "contacts.txt"

def banner():
    print(colored("recon-bluster version {}" .format(version), "green", attrs=['bold']))

def banner_recon(text,colour):
    print(colored("\n--------------------------------------------", "{}" .format(colour), attrs=['bold']))
    print(colored("{}" .format(text), "{}" .format(colour), attrs=['bold']))
    print(colored("--------------------------------------------", "{}" .format(colour), attrs=['bold']))

def passive_subdomain_enum(args):

    banner_recon("Passive subdomain enumeration", "yellow")
    
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

    ## extracting contact
    subprocess.call("grep '@' {} | anew {} >/dev/null 2>&1" .format(subdomains_output, contacts_output), shell=True)
    subprocess.call("sed -i -r '/@|\*|cpanel\.|cpcalendars\.|cpcontacts\.|webmail\.|webdisk\./d' {}" .format(subdomains_output), shell=True)
    subprocess.call("sed -i -r '/@|\*|cpanel\.|cpcalendars\.|cpcontacts\.|webmail\.|webdisk\./d' {}" .format(new_subdomains_output), shell=True)

def intel_domain_enum(args):

    banner_recon("Intelligence domain enumeration", "yellow")
    
    ## amass intel
    recon = log.progress("Executing amass intel")
    recon.status('In progress...')
    subprocess.call("amass intel -whois -d {} | anew {} > {}" .format(args.domain, intel_domains_output, new_intel_domains_output), shell=True)
    recon.success("Done")

def urls_enum(args):

    banner_recon("URLs enumeration", "yellow")
    
    ## httpx
    recon = log.progress("Executing httpx")
    recon.status('In progress...')
    subprocess.call("httpx -l {} -ports 80,443,8009,8080,8081,8090,8180,8443 -timeout 10 -threads 200 --follow-redirects -silent | anew {} > {}" .format(new_subdomains_output, httpx_output, tmp_httpx_output), shell=True)
    recon.success("Done")

    ## waybackurls
    recon = log.progress("Executing waybackurls")
    recon.status('In progress...')
    subprocess.call("cat {} | waybackurls | anew {} > {}" .format(tmp_httpx_output, urls_output,tmp_urls_output), shell=True)
    recon.success("Done")

    ## gau
    recon = log.progress("Executing gau")
    recon.status('In progress...')
    subprocess.call("cat {} | gau | anew {} >> {}" .format(tmp_httpx_output, urls_output, tmp_urls_output), shell=True)
    recon.success("Done")
    
    ## hakrawler
    recon = log.progress("Executing hakrawler")
    recon.status('In progress...')
    subprocess.call("cat {} | hakrawler -plain -usewayback | anew {} >> {}" .format(tmp_httpx_output, urls_output, tmp_urls_output), shell=True)
    recon.success("Done")
    
def generate_target_file(args):

    banner_recon("Generating target file", "yellow")
    
    ## gf sqli
    recon = log.progress("Executing gf sqli")
    recon.status('In progress...')
    subprocess.call("cat {} | gf sqli | unew -combine | anew {} >/dev/null 2>&1" .format(tmp_urls_output, gf_sqli_output), shell=True)
    recon.success("Done")

    ## gf xss
    recon = log.progress("Executing gf xxs")
    recon.status('In progress...')
    subprocess.call("cat {} | gf xss | unew -combine | anew {} >/dev/null 2>&1" .format(tmp_urls_output, gf_xss_output), shell=True)
    recon.success("Done")

    ## gf ssrf
    recon = log.progress("Executing gf ssrf")
    recon.status('In progress...')
    subprocess.call("cat {} | gf ssrf | unew -combine | anew {} >/dev/null 2>&1" .format(tmp_urls_output, gf_ssrf_output), shell=True)
    recon.success("Done")

    ## gf upload-fields
    recon = log.progress("Executing gf upload-fields")
    recon.status('In progress...')
    subprocess.call("cat {} | gf upload-fields | anew {} >/dev/null 2>&1" .format(tmp_urls_output, gf_upload_fields_output), shell=True)
    recon.success("Done")
    
def clean_result():
    
    ## cleaning result
    recon = log.progress("Cleaning result")
    recon.status('In progress...')
    subprocess.call("rm tmp*.txt", shell=True)
    recon.success("Done")

def summary():
    
    banner_recon("Summary", "green")
    
    ## generating summary
    subprocess.call("wc -l *.txt", shell=True)

if __name__ == "__main__":

    ## version
    banner()

    ## parse argument
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", action="store", help="Target domain", required=True)
    args = parser.parse_args()
    
    if len(sys.argv[1:])==0:
        parser.print_help()
        parser.exit()
    
    try:

        ## passive enum
        passive_subdomain_enum(args)

        ## intel enum
        intel_domain_enum(args)

        ## urls enum
        urls_enum(args)

        ## generating target file
        generate_target_file(args)
    
        ## result
        clean_result()
        summary()
    
    except Exception as error:

        print(error)
        raise
