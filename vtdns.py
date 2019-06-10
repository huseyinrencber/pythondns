import time
import requests
import csv
import whois
from datetime import datetime
from time import strptime
format = '%Y-%m-%d %H:%M:%S'
from datetime import timedelta

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

#from __future__ import print_function



apikey = '412c99a2c965419816e0da1eacfd6008ce1d*******************'  # API KEY #

requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False
domainErrors = []
delay = {}


# scan the domain to ensure results are fresh
def DomainScanner(domain):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url': domain}

    # attempt connection to VT API and save response as r
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)

    # sanitize domain after upload for safety
    domainSani = domain.replace('.', '[.]')

    print(domainSani)
    print(r)

    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # print error if the scan had an issue
            if jsonResponse['response_code'] is not 1:
                print('There was an error submitting the domain for scanning.')
                print(jsonResponse['verbose_msg'])
            elif jsonResponse['response_code'] == -2:
                print('{!s} is queued for scanning.'.format(domainSani))
                delay[domain] = 'queued'
            else:
                print('{!s} was scanned successfully.'.format(domainSani))

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
            domainErrors.append(domain)

        # return domain errors for notifying user when script completes
        time.sleep(15)  
        return delay

    # API TOS issue handling
    elif r.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')


def DomainReportReader(domain, delay):
    # sleep 15 to control requests/min to API. Public APIs only allow for 4/min threshold,
    # you WILL get a warning email to the owner of the account if you exceed this limit.
    # Private API allows for tiered levels of queries/second.

    # check to see if we have a delay in the report being available
    # if we do, delay for a little bit longer in hopes of the report being ready
    if delay:
        if domain in delay:
            time.sleep(10)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': domain}

    # attempt connection to VT API and save response as r
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)
        exit(1)

    # sanitize domain after upload for safety
    domainSani = domain.replace('.', '[.]')
    # handle ValueError response which may indicate an invalid key or an error with scan
    # if an except is raised, add the domain to a list for tracking purposes
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            # print error if the scan had an issue
            if jsonResponse['response_code'] is 0:
                print('There was an error submitting the domain for scanning.')
                pass

            elif jsonResponse['response_code'] == -2:
                print('Report for {!r} is not ready yet. Please check the site\'s report.'.format(domainSani))

            else:
                print('Report is ready for', domainSani)

            # print(jsonResponse)
            permalink = jsonResponse['permalink']
            scandate = jsonResponse['scan_date']
            positives = jsonResponse['positives']
            total = jsonResponse['total']

            data = [scandate, domainSani, positives, total, permalink]
            return data

        except ValueError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
            domainErrors.append(domainSani)

        except KeyError:
            print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
            domainErrors.append(domainSani)

    # API TOS issue handling
    elif r.status_code == 204:
        print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
        print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
              'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
        time.sleep(10)
        DomainReportReader(domain, delay)

# open results file and write header
try:
    rfile = open('results.txt', 'w+')
    dataWriter = csv.writer(rfile, delimiter = ',')
    header = ['Scan Date', 'Domain', '# of Positive Scans', '# of Total Scans', 'Permalink']
    dataWriter.writerow(header)

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)


# CHANGE TO TEXT FILE PATH. ONE DOMAIN PER LINE! #
try:
    # read domains from file and pass them to DomainScanner and DomainReportReader
    with open('domains.txt', 'r') as infile:  
        for domain in infile:
            domain = domain.strip('\n')
            try:
                delay = DomainScanner(domain)
                data = DomainReportReader(domain, delay)
                if data:
                    dataWriter.writerow(data)
                    time.sleep(15)  # wait for VT API rate limiting
            except Exception as err:  # keeping it
                print('Encountered an error but scanning will continue.', err)
                pass

except IOError as ioerr:
    print('Please ensure the file is closed.')
    print(ioerr)

# inform errors
count = len(domainErrors)
if count > 0:
    print('There were {!s} errors scanning domains'.format(count))
print(domainErrors)


f1 =open("domains.txt", "r")
d1 = f1.read()
domain=whois.query(str(d1))
time1 = domain.creation_date
time2 = datetime.now()
print time1
file=open("results2.txt","w")
file.write(str(time1))
file.close
#read file
f3=open("results2.txt","r")
date1=f3.read()
#delta will be added
if '2019-05' in date1:
	print "potential malware whois"
else:
	print "non malware whois"
f4=open("results.txt","r")
vt=f4.read()
if ',0,' in vt:
	print "non malware vt"
else:
	print "potential malware vt"
#DNS query
# nslookup/dig:
qname = dns.name.from_text('gmaiil.com')
q = dns.message.make_query(qname, dns.rdatatype.A)
#print('The query is:')
#print(q)
#print('')
r = dns.query.udp(q, '8.8.8.8')
#print('The response is:')
#print(r)
#print('')
#print('The nameservers are:')
ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.A)
#for rr in ns_rrset:
#	print(rr.target)
#print('')
#print('')
#if ( '2019' in date1 ) or ( ',0,' in vt):
#	print "dns block"
...


