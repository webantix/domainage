#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Create color pool
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
#
# Print header what ever happens
print bcolors.HEADER + """
     _                       _
    | |                     (_)
  __| | ___  _ __ ___   __ _ _ _ __   __ _  __ _  ___
 / _` |/ _ \| '_ ` _ \ / _` | | '_ \ / _` |/ _` |/ _ \\
| (_| | (_) | | | | | | (_| | | | | | (_| | (_| |  __/
 \__,_|\___/|_| |_| |_|\__,_|_|_| |_|\__,_|\__, |\___|
                                            __/ | v1.3
                                           |___/       """ + bcolors.ENDC
print ''
print 'DNS threat hunting tool by Duncan \'Webantix\' Alderson.'
print ''
# Are the required Python libraries installed?
from datetime import * #Get date and delta
import time #To be able to compare file age with time now
import sys #To collect command line arguments
import signal #To collect Ctrl-C exit
import optparse #To handle the options
import urllib2 #Be able to download top million list
import zipfile #be able to unzip download
import logging #To handle tldextract logging (issue:4)
import os.path #To check if file exists
try:
    import whois #To do the whois lookup
except ImportError:
    print 'You will need to type \"sudo pip install python-whois\" for this to work.'
    exit()
try:
    import tldextract
    from tldextract.tldextract import LOG #To handle tldextract logging (issue:4)
except ImportError:
    print 'You will need to type \"sudo pip install tldextract\" for this to work.'
    exit()
# Collect options from commandline
parser = optparse.OptionParser()
parser.add_option('-d', dest='domain', help='Use with a single domain name')
parser.add_option('-f', dest='file', help='Use a file with a domain name on each line.')
parser.add_option('-b', dest='bro', help='Use a Bro IDS DNS log file.')
(options, args) = parser.parse_args()
# Set logging level to handle tldextract error
logging.basicConfig(level=logging.CRITICAL) #To handle tldextract logging (issue:4)

def main():
#Set Variable
    d = None # Domain holder

#Collect option flag set
    if options.domain:
        d = get_domain_list()
    elif options.file:
        d = get_textfile()
    elif options.bro:
        d = get_bro_log()
    else:
        print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' usage:'
        print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' domainage.py -f domainlist.txt'
        print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' domainage.py -d webantix.net (no output file)'
        print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' domainage.py -b /nsm/bro/log/dns.log'
        print ''
        exit()
    analyse(d)


def get_domain_list():
    # If a single domain being queried
    d = [options.domain]
    return(d)

def get_textfile():
    # Collect file from command
    try:
        d = open(options.file).read().splitlines()
    except IOError as e:
        print e
        exit()
    return(d)

def get_bro_log():
    # Collect bro log file location
    try:
        bro = open(options.bro).read().splitlines()
    except IOError as e:
        print e
        exit()
    d = []
    for line in bro:
        if line[0] != '#': #remove header and footers
            line =  [splits for splits in line.split("\t") if splits is not ""]
            dom = tldextract.extract(line[8]) #load string into TLD Extract
            line = dom.registered_domain #replace string with registered domain to query
            if line not in d:
                d.append(line)
    return(d)

def download_alexa():
    # Download and unzip Alexa
    download = urllib2.urlopen('http://s3.amazonaws.com/alexa-static/top-1m.csv.zip')
    with open('top-1m.csv.zip','wb') as output:
        output.write(download.read())
    print ' %s[!]%s Alexa downloaded. Extracting.' % (bcolors.WARNING, bcolors.ENDC)
    zip = zipfile.ZipFile('top-1m.csv.zip', 'r')
    zip.extractall('./')
    zip.close()
    print ' %s[!]%s Alexa extracted.' % (bcolors.WARNING, bcolors.ENDC)

def analyse(d):
    c = 0 # Count holder
    # Get today's date to get delta
    today = datetime.now()
    # Start creating log file
    if not options.domain:
        fo = open(str(today.strftime('%Y-%m-%d')) + "-domainage.log", "a+")
        fo.write( "Date of Test;Domain;Creation Date;Age(years);Log Message\n");

    # Do whois lookup
    if d:
        t1 = time.time() #Time for percentage counter and Alexa age compare
        # Tell user how many unique domians are in file
        print ' %s[-]%s Starting analysis on %s domain names.' % (bcolors.OKBLUE, bcolors.ENDC, len(d))
        # Check to see if it is in the Alexa list
        print ' %s[-]%s Loading Alexa top million.' % (bcolors.OKBLUE, bcolors.ENDC)
        # Does Alexa file exist?
        alexa_exist = os.path.isfile('top-1m.csv')
        if alexa_exist:
            # How old is the list? Over 7 days old, down load new.
            t1 = time.time()
            t2 = os.path.getmtime('top-1m.csv')
            if t1 - t2 < 604800:
                print ' %s[-]%s Alexa file is under 7 days old. We will use this one.' % (bcolors.OKBLUE, bcolors.ENDC)
            else:
                print ' %s[!]%s Alexa file is old. Downloading new file now.' % (bcolors.WARNING, bcolors.ENDC)
                download_alexa()
        else:
            print ' %s[!]%s No Alexa file found. Downloading now.' % (bcolors.WARNING, bcolors.ENDC)
            download_alexa()
        alexa = open('top-1m.csv').read()
        print ' %s[-]%s Alexa succesfully loaded.' % (bcolors.OKBLUE, bcolors.ENDC)

        for i in d:
            if time.time() - t1 > 10:
                percent = 100 * float(c) / float(len(d))
                print ' %s[-]%s %s%% complete.' % (bcolors.OKBLUE, bcolors.ENDC, int(percent))
                t1 = time.time()
            c = c + 1
            dom = tldextract.extract(i) #load string into TLD Extract
            ii = dom.registered_domain #replace string with registered domain to query


            # is domain in Alexa
            a = ii in alexa
            if a:
                if not options.domain:
                    fo.write('%s;%s;-;-;This domain is found in the Alexa top Million list. Most likely not malicous.\n' % (today, ii))
                # print ' %s[+]%s %s is found in the Alexa top Million list. Most likely not malicous.' % (bcolors.OKBLUE, bcolors.ENDC, ii)
                continue
            # is domain a .GOV? If so skip
            if dom.suffix == 'gov':
                if not options.domain:
                    fo.write('%s;%s;-;-;This domain is hosted on the the GOV Whois server which has no creation date.\n' % (today, ii))
                print ' %s[!]%s %s is hosted on the the GOV Whois server which has no creation date.' % (bcolors.WARNING, bcolors.ENDC, ii)
                continue
            # is domain a .TO? If so skip
            if dom.suffix == 'to':
                if not options.domain:
                    fo.write('%s;%s;-;-;This domain is hosted on the the Tonic (Tongan) Whoisd server which has no information.\n' % (today, ii))
                print ' %s[!]%s %s is hosted on the the Tonic (Tongan) Whoisd server which has no information.' % (bcolors.WARNING, bcolors.ENDC, ii)
                continue
            # is domain a .IO? If so skip
            if dom.suffix == 'io':
                if not options.domain:
                    fo.write('%s;%s;-;-;This domain is hosted on the the IO Whois server which has no creation date.\n' % (today, ii))
                print ' %s[!]%s %s is hosted on the the IO Whois server which has no creation date.' % (bcolors.WARNING, bcolors.ENDC, ii)
                continue
            if len(ii) > 3 and '.' in ii: #Is the domain name long enough and have a dot.
                try:
                    w = whois.whois(ii)
                    # Compare dates between now and creation dates
                    d1 = w.creation_date
                    if d1:
                        if isinstance(d1, list): #true
                            d2 = (today-d1[0])
                        else:
                            d2 = (today-d1)
                        d3 = d2.days / 365
                        if d3 >= 1:
                            #print bcolors.OKBLUE + ' [+] ' + bcolors.ENDC + ii + ' is ' + str(d3) + ' years old'
                            if not options.domain:
                                fo.write(str(today) + ';' + str(ii) + ';' + str(d1) + ';' + str(d3) + ';' + '\n');
                        else:
                            print bcolors.FAIL + ' [!] ' + bcolors.ENDC + ii + ' is ' + str(d3) + ' years old, this may be an issue.'
                            if not options.domain:
                                fo.write(str(today) + ';' + str(ii) + ';' + str(d1) + ';' + str(d3) + ';' + '\n');
                    else:
                        print bcolors.WARNING + ' [!]' + bcolors.ENDC + ' That\'s weird looks like the Creation date is blank. You may need to do ' + ii + ' manually.[' + w + ']'
                        #print bcolors.WARNING + ' [!]' + bcolors.ENDC + ' If creation date available in normal whois raise an issue on github. https://github.com/webantix/domainage/issues'

                except KeyboardInterrupt:
                    print ''
                    print 'Leaving so early =('
                    sys.exit()
                except (whois.parser.PywhoisError):
                    print ' %s[!]%s %s does not look to be registered.' % (bcolors.FAIL, bcolors.ENDC, ii)
                except:
                    e = sys.exc_info()
                    error = str(e)
                    print ' %s[!]%s An error happened with %s. Please manually follow this up.' % (bcolors.WARNING, bcolors.ENDC, ii)
                    #print e


        print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' Analysis complete.'
    if not options.domain:
        fo.close();
        print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' Log file name:', fo.name

    #create space at end of output
    print ''



main()
