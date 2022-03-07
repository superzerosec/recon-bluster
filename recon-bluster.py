#!/usr/bin/env python3

import subprocess, os, argparse, sys
from pwn import *
from termcolor import colored
from threading import Thread

## initialse
version = 0.4
subdomains_output = "subdomains.txt"
new_subdomains_output = "subdomains_new.txt"
intel_domains_output = "intel_domains.txt"
new_intel_domains_output = "intel_domains_new.txt"
new_httpx_output = "subdomains_httpx_new.txt"
new_urls_output = "subdomains_urls_new.txt"
httpx_output = "subdomains_httpx.txt"
urls_output = "subdomains_urls.txt"
gf_sqli_output = "target_sqli.txt"
gf_xss_output = "target_xss.txt"
gf_ssrf_output = "target_ssrf.txt"
gf_upload_fields_output = "target_upload_fields.txt"
contacts_output = "contacts.txt"

## saving origin path
orig_path = os.getcwd()

def generate_target_file(domain, recon_log, domain_folder):
    
    ## gf sqli
    recon_log.status('Generating target file: Executing gf sqli...')
    subprocess.call("cat {} | gf sqli | unew -combine | anew {} >/dev/null 2>&1" .format(os.path.join(domain_folder, new_urls_output), os.path.join(domain_folder, gf_sqli_output)), shell=True)

    ## gf xss
    recon_log.status('Generating target file: Executing gf xxs...')
    subprocess.call("cat {} | gf xss | unew -combine | anew {} >/dev/null 2>&1" .format(os.path.join(domain_folder, new_urls_output), os.path.join(domain_folder, gf_xss_output)), shell=True)

    ## gf ssrf
    recon_log.status('Generating target file: Executing gf ssrf...')
    subprocess.call("cat {} | gf ssrf | unew -combine | anew {} >/dev/null 2>&1" .format(os.path.join(domain_folder, new_urls_output), os.path.join(domain_folder, gf_ssrf_output)), shell=True)

    ## gf upload-fields
    recon_log.status('Generating target file: Executing gf upload-fields...')
    subprocess.call("cat {} | gf upload-fields | anew {} >/dev/null 2>&1" .format(os.path.join(domain_folder, new_urls_output), os.path.join(domain_folder, gf_upload_fields_output)), shell=True)

def urls_enum(domain, recon_log, domain_folder):
    
    ## httpx
    recon_log.status('URLs enumeration: Executing httpx...')
    subprocess.call("httpx -l {} -ports 80,443,8009,8080,8081,8090,8180,8443 -timeout 10 -threads 200 --follow-redirects -silent -json | jq -r .url | anew {} > {}" .format(os.path.join(domain_folder, new_subdomains_output), os.path.join(domain_folder, httpx_output), os.path.join(domain_folder, new_httpx_output)), shell=True)

    ## waybackurls
    recon_log.status('URLs enumeration: Executing waybackurls...')
    subprocess.call("cat {} | waybackurls | anew {} > {}" .format(os.path.join(domain_folder, new_httpx_output), os.path.join(domain_folder, urls_output), os.path.join(domain_folder, new_urls_output)), shell=True)

    ## gau
    #recon_log.status('URLs enumeration: Executing gau...')
    #subprocess.call("cat {} | gau | anew {} >> {}" .format(os.path.join(domain_folder, new_httpx_output), os.path.join(domain_folder, urls_output), os.path.join(domain_folder, new_urls_output)), shell=True)
    
    ## hakrawler
    recon_log.status('URLs enumeration: Executing hakrawler...')
    subprocess.call("cat {} | hakrawler | anew {} >> {}" .format(os.path.join(domain_folder, new_httpx_output), os.path.join(domain_folder, urls_output), os.path.join(domain_folder, new_urls_output)), shell=True)

def intel_domain_enum(domain, recon_log, domain_folder):
    
    ## amass intel
    recon_log.status('Intelligence domain enumeration: Executing amass intel...')
    subprocess.call("amass intel -whois -d {} | anew {} > {}" .format(domain, os.path.join(domain_folder, intel_domains_output), os.path.join(domain_folder, new_intel_domains_output)), shell=True)

def passive_subdomain_enum(domain, recon_log, domain_folder):
    
    ## assetfinder
    recon_log.status('Passive subdomain enumeration: Executing assetfinder...')
    subprocess.call("assetfinder -subs-only {} | anew {} > {}" .format(domain, os.path.join(domain_folder, subdomains_output), os.path.join(domain_folder, new_subdomains_output)), shell=True)

    ## subfinder
    recon_log.status('Passive subdomain enumeration: Executing subfinder...')
    subprocess.call("subfinder -silent -d {} | anew {} >> {}" .format(domain, os.path.join(domain_folder, subdomains_output), os.path.join(domain_folder, new_subdomains_output)), shell=True)

    ## crt.sh
    recon_log.status('Passive subdomain enumeration: Executing crt.sh...')
    subprocess.call("curl -s 'https://crt.sh/?q=%25.{}&output=json' | jq -r '.[].name_value' | anew {} >> {}" .format(domain, os.path.join(domain_folder, subdomains_output), os.path.join(domain_folder, new_subdomains_output)), shell=True)

    ## amass enum
    #recon_log.status('Passive subdomain enumeration: Executing amass enum...')
    #subprocess.call("amass enum -silent -passive -d {} | anew {} >> {}" .format(domain, os.path.join(domain_folder, subdomains_output), os.path.join(domain_folder, new_subdomains_output)), shell=True)

    ## extracting contact
    subprocess.call("grep '@' {} | anew {} >/dev/null 2>&1" .format(os.path.join(domain_folder, subdomains_output), os.path.join(domain_folder, contacts_output)), shell=True)
    subprocess.call("sed -i -r '/@|\*|cpanel\.|cpcalendars\.|cpcontacts\.|webmail\.|webdisk\./d' {}" .format(os.path.join(domain_folder, subdomains_output)), shell=True)
    subprocess.call("sed -i -r '/@|\*|cpanel\.|cpcalendars\.|cpcontacts\.|webmail\.|webdisk\./d' {}" .format(os.path.join(domain_folder, new_subdomains_output)), shell=True)

def recon(domain):

    try:
        
        ## log progress
        recon_log = log.progress(domain)

        ## domain folder path
        domain_folder = os.path.join(orig_path,domain)

        ## create target folder
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        ## change dir to target folder
        os.chdir(domain_folder)

        ## passive enum
        passive_subdomain_enum(domain, recon_log, domain_folder)

        ## intel enum
        #intel_domain_enum(domain, recon_log, domain_folder)

        ## urls enum
        urls_enum(domain, recon_log, domain_folder)

        ## generating target file
        generate_target_file(domain, recon_log, domain_folder)

        ## progress done
        recon_log.success("Done")

    except Exception as error:

        print(error)
        raise

def banner():
    print(colored("recon-bluster version {}" .format(version), "green", attrs=['bold']))

if __name__ == "__main__":

    ## version
    banner()

    ## parse argument
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", action="store", help="Target domain", default=False)
    parser.add_argument("-l", "--list", action="store", help="List of target domain saperated with new line", default=False)
    args = parser.parse_args()
    
    if args.domain is not False:
        
        ## single target domain
        domain = args.domain
        recon(domain)

    elif args.list is not False:
        
        ## initialise threads list
        threads = list()

        ## multiple target domain
        with open(args.list) as file:

            ## create multi-threaded
            for domain in file:
                domain = domain.rstrip()
                t = Thread(target=recon, args=(domain,))
                threads.append(t)
                t.start()
            
            ## wait for all threads to complete
            for t in threads:
                t.join()

    else:

        parser.print_help()
        parser.exit()
