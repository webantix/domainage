# Domainage

## Introduction
Domainage is a small tool that looks for young domian names that may be trying to look like other domains. If the domain is under a year old it will let you know. You can either ask it to analyse a single domain, text file with a list of domains or it's main reason to analyse Bro DNS log files.


###usage:

domainage.py -f domainlist.txt

domainage.py -d webantix.net (no output file)

domainage.py -b /nsm/bro/log/dns.log
