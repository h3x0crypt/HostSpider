#!/usr/local/bin/python3

'''
-------------------------------------------------------------------------------
PROJECT:    FINDMYASS Domain information gathering Tool
AUTHOR:     h3x0crypt @ GitHub.com
-------------------------------------------------------------------------------
INFO:       I've coded this small tool it may help you
            Domain informations Gathering such as whois , DNS Records and Subdomains
            and colleting them into a report file .
            IMPORTANT : I've spent time coding this to share it with the community ,
            i hope you like it , meanwhile i'm not really experienced in python
            but i'm doing my best to learn and practice more every day !
            ./exit
'''

# python modules
import requests, json, sys, os, time, validators, signal
from jinja2 import *
from bs4 import BeautifulSoup
from datetime import datetime

# Colors
class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

# I LIKE ASCII ART
def banner():
    print(f"""{bcolors.OKGREEN}{bcolors.BOLD}
        ────▐──▌─────▐──▌────
        ───▐▌─█───────█─▐▌───
        ──▄█──▀▀▄▌▄▐▄▀▀──█▄──
        ─▐█─▄█▀▄█████▄▀█▄─█▌─    ______ _____ _   _ _____  __  ____     __       _____ _____ 
        ──▀▀─▄▄▄█████▄▄▄─▀▀──   |  ____|_   _| \ | |  __ \|  \/  \ \   / //\    / ____/ ____|
        ───▄█▀─▄▀███▀▄─▀█▄───   | |__    | | |  \| | |  | | \  / |\ \_/ //  \  | (___| (___  
        ─▄█──▄▀──███──▀▄──█▄─   |  __|   | | | . ` | |  | | |\/| | \   // /\ \  \___ \\___ \ 
        ▐█───█───▐█▌───█───█▌   | |     _| |_| |\  | |__| | |  | |  | |/ ____ \ ____) |___) |
        ─█────█───▀───█────█─   |_|    |_____|_| \_|_____/|_|  |_|  |_/_/    \_\_____/_____/ 
        ─▀█───█───────█───█▀─   {bcolors.WARNING}Project : Domain information gathering Tool{bcolors.OKGREEN}
        ──█────█─────█────█──   {bcolors.WARNING}Version : 1.0{bcolors.OKGREEN}
        ───█───█─────█───█───   {bcolors.WARNING}Author  : h3x0{bcolors.OKGREEN}
        ────▌───▌───▐───▐────   {bcolors.WARNING}Github  : https://github.com/h3x0crypt{bcolors.ENDC}
    """)

# what machine we are working on ?
class cmd:
    machineOs = os.name
    if machineOs == 'posix':
        clear = 'clear'
        create_dir = 'mkdir'
        install_modules = 'pip3 install -r requirements.txt'

    else:
        clear = 'cls'
    create_dir = 'mkdir'
    current_dir = os.getcwd()

# I'm a linux lover
def install_requirements():
    print(f"{bcolors.WARNING}   Installing Required Python3 modules ... {bcolors.ENDC}")
    try:
        os.system(cmd.install_modules)
        os.system(cmd.clear)
    except :
        sys.exit('i guess you are using windows , sorry bro , get LINUX get LIFE')
#pretty quit

def quit(signum, frame):
    print(f"\n\n{bcolors.WARNING}     ./ Exiting ... \n")
    sys.exit(0)

# check directory
def checkDir(dirname):
    return(os.path.isdir(dirname))

# check dict key existance
def checkKey(dict, key):
    if key in dict.keys():
        return True
    else:
        return False

# whois data
def fetchWhoisData(domain):
    try:
        payload={'q':domain}
        r = requests.get('https://lookup.icann.org/api/whois', payload)
        response = json.loads(r.text)
        if(checkKey(response,'errorCode')):
            if response['errorCode'] == 7:
                domain_exist = False
            else:
                domain_exist = True
            status = False
            ret_data = response['message']
        else:
            domain_exist = True
            status = True
            for record in response['records']:
                ret_data = record['serverResponse']['rawResponse'].replace("\r\n", "<br>")
        return domain_exist,status,ret_data
    except Exception as e:
        print(e)

# fetch domain info
def fetchDomainData(domain):
    try:
        reqbuild = requests.get(f'https://securitytrails.com/list/apex_domain/{domain}')
        soup = BeautifulSoup(reqbuild.text, features="html5lib")
        data = json.loads(soup.find(id="__NEXT_DATA__").contents[0])
        buildid = data['buildId']

        payload = {'domain': domain}
        url = f'https://securitytrails.com/_next/data/{buildid}/list/apex_domain/{domain}.json'
        r = requests.get(url, payload)
        response = json.loads(r.content)
        return domain,response
    except Exception as e:
        print(e)

# sorting fetched data
def sortDomainData(domain,data):
    # that's weird but it's like that
    apex_status = data['pageProps']['apexDomainData']['success']
    ns_status = data['pageProps']['dnsData']['success']
    if (apex_status == True & ns_status == True):
        # getting records lists
        alexa_rank = data['pageProps']['dnsData']['data']['alexa_rank']

        subdomain_count = data['pageProps']['subdomainsCount']
        apex_records = data['pageProps']['apexDomainData']['data']['records']
        # A records
        dns_a_records = data['pageProps']['dnsData']['data']['current_dns']['a']
        if checkKey(dns_a_records, 'values'):
            dns_a_records = dns_a_records['values']
        # AAAA records
        dns_aaaa_records = data['pageProps']['dnsData']['data']['current_dns']['aaaa']
        if checkKey(dns_aaaa_records, 'values'):
            dns_aaaa_records = dns_aaaa_records['values']
        # MX records
        dns_mx_records = data['pageProps']['dnsData']['data']['current_dns']['mx']
        if checkKey(dns_mx_records, 'values'):
            dns_mx_records = dns_mx_records['values']
        # NS records
        dns_ns_records = data['pageProps']['dnsData']['data']['current_dns']['ns']
        if checkKey(dns_ns_records, 'values'):
            dns_ns_records = dns_ns_records['values']
        # SOA records
        dns_soa_records = data['pageProps']['dnsData']['data']['current_dns']['soa']
        if checkKey(dns_soa_records, 'values'):
            dns_soa_records = dns_soa_records['values']
        # TXT records
        dns_txt_records = data['pageProps']['dnsData']['data']['current_dns']['txt']
        if checkKey(dns_txt_records, 'values'):
            dns_txt_records = dns_txt_records['values']
        #Lists
        returned_data_subdomains = []
        returned_data_a = []
        returned_data_aaaa = []
        returned_data_mx = []
        returned_data_ns = []
        returned_data_txt = []
        returned_data_soa = []
        try:
            # appending domain records
            for record in apex_records:
                line = record['hostname'],record['host_provider'],record['mail_provider']
                returned_data_subdomains.append(line)
            # appending dns records
            for record in dns_a_records:
                line = record['ip'],record['ip_organization']
                returned_data_a.append(line)
            for record in dns_aaaa_records:
                line = record['ipv6'],record['ipv6_organization']
                returned_data_aaaa.append(line)
            for record in dns_mx_records:
                line = record['hostname'],record['hostname_organization'],record['priority']
                returned_data_mx.append(line)
            for record in dns_ns_records:
                line = record['nameserver'],record['nameserver_organization']
                returned_data_ns.append(line)
            for record in dns_soa_records:
                for key in record:
                    line = record[key]
                    returned_data_soa.append(line)
            for record in dns_txt_records:
                for key in record:
                    line = record[key]
                    returned_data_txt.append(line)
            # detect if cloudflare
            if returned_data_a[0][1] == 'Cloudflare, Inc.':
                isCloudflare = True
            else:
                isCloudflare = False
            returned_data = {
                'domain' : domain,
                'alexa' : alexa_rank,
                'subdomains_count': subdomain_count,
                'iscloudflare':isCloudflare,
                'subdomains':returned_data_subdomains,
                'a_records':returned_data_a,
                'aaaa_records':returned_data_aaaa,
                'mx_records':returned_data_mx,
                'ns_records':returned_data_ns,
                'soa_records': returned_data_soa,
                'txt_records':returned_data_txt
            }
            return True, returned_data
        except Exception as e:
            print(e)
            return False,None
    else:
        return False,None

# generate report
def generateReport(data,domain):
    try:
        report_number = int(time.time())
        template = Template(open('lib/report_tpl.html').read())
        data['report_number'] = report_number
        tpl = template.render(data=data)
        if checkDir(f'reports/{domain}') == False:
            os.system(f'{cmd.create_dir} reports/{domain}')
        f = open(f'reports/{domain}/report-{report_number}.html', 'w')
        f.write(tpl)
        f.close()
        return report_number
    except Exception as e:
        print(e)

def main():
    package_file = open("lib/package.json").read()
    package_data = json.loads(package_file)
    if package_data['package'] == False:
        install_requirements()
        os.system(cmd.clear)
        package_data['package'] = True
        f = open("lib/package.json", "w+")
        f.write(json.dumps(package_data))
        f.close()
    banner()
    while True:
        try:
            domain = str(input(f"\n    {bcolors.BOLD}> Domain name without (http/https) : {bcolors.ENDC}"))
        except ValueError:
            print(F"\n    {bcolors.FAIL}<ERROR> SORRY I DIDN'T UNDERSTAND THAT{bcolors.ENDC}\n")
            continue
        if validators.domain(domain):
            break
        else:
            print(F"\n    {bcolors.FAIL}<ERROR> PLEASE ENTER A VALID DOMAIN NAME{bcolors.ENDC}\n")
            continue
    print(f"\n        {bcolors.OKCYAN}{bcolors.BOLD} ./ Gathering WHOIS data ...{bcolors.ENDC}")
    is_valid_domain,status,whois_resp = fetchWhoisData(domain)
    if is_valid_domain:
        print(f"\n        {bcolors.OKCYAN}{bcolors.BOLD} ./ Gathering data from securitytrails ...{bcolors.ENDC}")
        domain, data = fetchDomainData(domain)
        status, data = sortDomainData(domain, data)
        print(f"\n        {bcolors.HEADER}      <INFO> DOMAIN     :  {bcolors.ENDC}{bcolors.BOLD}{data['domain']}{bcolors.ENDC}")
        print(f"\n        {bcolors.HEADER}      <INFO> SUBDOMAINS :  {bcolors.ENDC}{bcolors.BOLD}{data['subdomains_count']}{bcolors.ENDC}")
        print(f"\n        {bcolors.HEADER}      <INFO> ALEXA RANK :  {bcolors.ENDC}{bcolors.BOLD}{data['alexa']}{bcolors.ENDC}")
        print(f"\n        {bcolors.HEADER}      <INFO> CLOUDFLARE :  {bcolors.ENDC}{bcolors.BOLD}{data['iscloudflare']}{bcolors.ENDC}")
        if status:
            data['whois'] = whois_resp
            data['report_time'] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            print(f"\n        {bcolors.OKCYAN}{bcolors.BOLD} ./ Generating The Report ...{bcolors.ENDC}")
            report_id = generateReport(data, domain)
            report_location = f'{cmd.current_dir}/reports/{domain}/report-{report_id}.html'
            print(f"\n        {bcolors.OKGREEN} <SUCCES> Report path : {bcolors.WARNING}{bcolors.BOLD}{report_location}{bcolors.ENDC}\n")
        else:
            print(f"\n        {bcolors.FAIL} <ERROR> UNKOWN ERROR {bcolors.ENDC}\n")
            sys.exit()
    else:
        print(f"\n        {bcolors.FAIL} <ERROR> {domain} DOESN'T EXIST {bcolors.ENDC}\n")
        sys.exit()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, quit)
    main()