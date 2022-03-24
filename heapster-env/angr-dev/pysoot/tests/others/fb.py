#!/usr/bin/env python

from pysoot.lifter import Lifter
import datetime
import logging
import os
import sys

sys.stdout.flush()
sys.stderr.flush()

print "*"*1000
print "START\n\n"
print datetime.datetime.now()

if len(sys.argv) > 1:
    finput = sys.argv[1]
else:
    finput = "/home/ubuntu/com.facebook.orca.apk"

logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s', level=logging.DEBUG)
lifter = Lifter(input_file=finput, input_format="apk", android_sdk=os.path.join(os.path.expanduser("~"), "Android/Sdk/platforms/"))

print lifter.soot_wrapper.get_client_std()[-3000:]

print "*"*1000
print "END\n\n"
print datetime.datetime.now()

sys.stdout.flush()
sys.stderr.flush()

import IPython; IPython.embed()

import cPickle as pickle
fp = open("1.pickle","wb")
pickle.dump(lifter.classes, fp, pickle.HIGHEST_PROTOCOL)
fp.close()

# import IPython; IPython.embed()

# package: name='com.facebook.orca' versionCode='49249863' versionName='104.0.0.13.69' platformBuildVersionName='6.0-2166767'
# ~60GB, 13m on 64GB/16c
# ~48GB, 10m on 64GB/16c
# ~17GB (OOM when pickling), 11m on 32GB/8c

