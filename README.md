# Domainage

## Introduction
Domainage is a small tool that looks for young domian names that may be trying to look like other domains. If the domain is under a year old it will let you know. You can either ask it to analyse a single domain, text file with a list of domains or it's main reason to analyse Bro DNS log files.


### domainage.py Usage Instructions

domainage will search through DNS names to look for newly registered entries. Newly registered is defined as <1 year old. These may be
indicative of malicious sites.

-d $DNSname
This is "interactive" usage. You pass it a single DNS name and domainage.py will process it.

-f $filename
This will process a file with a list of domains, one domain per line.

-b $brolog
This option takes a dns.log file from bro and processes each domain.
For example:
zcat /nsm/bro/logs/2017-05-06/dns.22\:00\:00-23\:00\:00.log.gz > bro-dns.log
./domainage.py -b bro-dns.log
