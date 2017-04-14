#!/usr/bin/env python
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
                                            __/ | v1.1
                                           |___/       """ + bcolors.ENDC
print ''
print ' DNS threat hunting tool by Duncan \'Webantix\' Alderson.'
print ''
# Are the required Python libraries installed?
try:
    import whois #To do the whois lookup
    from datetime import * #Get date and delta
    import sys #To collect command line arguments
    import optparse #To handle the options
except ImportError:
    print 'You will need to type \"sudo pip install python-whois\" for this to work.'

# Collect options from commandline
parser = optparse.OptionParser()
parser.add_option('-d', '--domain', dest='domain', help='webantix.net')
parser.add_option('-f', '--file', dest='file', help='~/domains.txt')
(options, args) = parser.parse_args()


# Print usage if no options selected
if options.domain == None and options.file == None:
    print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' usage:'
    print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' domainage.py -f domainlist.txt'
    print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' domainage.py -d webantix.net (no output file)'
    print ''
#

# Set variables
d = None

# If a single domain being queried
if options.domain:
    d = [options.domain]
# Collect file from command
if options.file:
    d = open(options.file).read().splitlines()


# Get today's date to get delta
today = datetime.now()
if options.file:
    fo = open(str(today.strftime('%Y-%m-%d')) + "-domainage.log", "a+")
    fo.write( "Date of Test;Domain;Creation Date;Age(years)\n");

# Do whois lookup
if d:
    print bcolors.OKBLUE + ' [-] ' + bcolors.ENDC + 'Starting analysis'
    for i in d:
        print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' Analysing ' + i
        try:
            w = whois.whois(i)
# Compare dates between now and creation dates
            d1 = w.creation_date
            if d1:
                if isinstance(d1, list): #true
                    d2 = (today-d1[0])
                else:
                    d2 = (today-d1)
                d3 = d2.days / 365
                if d3 >= 1:
                    print bcolors.OKGREEN + ' [+] ' + bcolors.ENDC + i + ' is ' + str(d3) + ' years old'
                    if options.file:
                        fo.write(str(today) + ';' + str(i) + ';' + str(d1) + ';' + str(d3) + ';' + '\n');
                else:
                    print bcolors.FAIL + ' [!] ' + bcolors.ENDC + i + ' is ' + str(d3) + ' years old, this may be an issue.'
                    if options.file:
                        fo.write(str(today) + ';' + str(i) + ';' + str(d1) + ';' + str(d3) + ';' + '\n');
            else:
                print bcolors.WARNING + ' [!]' + bcolors.ENDC + ' That\'s weird looks like the Creation date is blank. You may need to do ' + i + ' manually.'
                print bcolors.WARNING + ' [!]' + bcolors.ENDC + ' If creation date available in normal whois raise an issue on github. http://github.com/webantix'

        except:
            print bcolors.FAIL + ' [X] ' + bcolors.ENDC + i + ' is not an existing domain. Could this be DGA activity?'
# Create out put of:
# Date of test : Domain : Creation Date : Expiry Date : Age(days) : Nameservers : Status

    print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' Analysis complete.'
if options.file:
    fo.close();
    print bcolors.OKBLUE + ' [-]' + bcolors.ENDC + ' Log file name:', fo.name

#create space at end of output
print ''
