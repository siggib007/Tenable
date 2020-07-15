'''
Script to Analyze Tenable Plugin ID 19506 output
Version: 1.0
Author Siggi Bjarnason Copyright 2020

Following packages need to be installed as administrator

'''
# Import libraries
import sys
import os
import string
import time
import csv

try:
	import tkinter as tk
	from tkinter import filedialog
	btKinterOK = True
except:
	print ("Failed to load tkinter, CLI only mode.")
	btKinterOK = False
# End imports

#Default values, overwrite these in the ini file
bTruncateTable = True   # Truncate the table prior to insert
bConvertBool = True     # Convert strings true/false into 1 and 0 for insert into database boolean field.
bRecordStats = True     # Log events and record stats in the database.

# Initialize stuff
strDelim = ","          # what is the field seperate in the input file
strCSVName = ""
iLoc = sys.argv[0].rfind(".")
strConf_File = sys.argv[0][:iLoc] + ".ini"
strScriptName = os.path.basename(sys.argv[0])
localtime = time.localtime(time.time())
gmt_time = time.gmtime()
iGMTOffset = (time.mktime(localtime) - time.mktime(gmt_time))/3600

def getInput(strPrompt):
    if sys.version_info[0] > 2 :
        return input(strPrompt)
    else:
        LogEntry("Please upgrade to python 3.x")
        sys.exit()
# end getInput

def LogEntry(strMsg):
	print (strMsg)

def isInt (CheckValue):
	# function to safely check if a value can be interpreded as an int
	if isinstance(CheckValue,int):
		return True
	elif isinstance(CheckValue,str):
		if CheckValue.isnumeric():
			return True
		else:
			return False
	else:
		return False

#Start doing stuff
print ("This is a script to parse the output from Tenable Plugin ID 19506. This is running under Python Version {0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2]))
now = time.asctime()
print ("The time now is {}".format(now))

