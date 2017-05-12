#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
print 'working'
t1 = time.time()
# import Alexa file and add to set
print t1
alexa = open('top-1m.csv').read()

# collect domain name

domains = ['webantix.net', 'facebook.com']

# is domian in alexa?

for domain in domains:
    result = domain in alexa
    print domain + ' in Alexa: ' + str(result)


t2 = time.time()
print 'finished'
print t2
print t2 - t1
