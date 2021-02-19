'''
Tenable API Script to pause jobs in progress or start paused jobs. 
Author Siggi Bjarnason Copyright 2020

Following packages need to be installed as administrator
pip install requests
pip install jason

'''
# Import libraries
from datetime import datetime, timedelta
import sys
import requests
import os
import string
import time
import urllib.parse as urlparse
import subprocess as proc
import json
import platform
# End imports

#avoid insecure warning
requests.urllib3.disable_warnings()

#Define few things
iChunkSize = 5000
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
iMaxRetry = 5 # Maximum number of times to retry an error
iTotalSleep = 0
tLastCall = 0
iErrCount = 0
lstSysArg = sys.argv
iSysArgLen = len(lstSysArg)

def getInput(strPrompt):
  if sys.version_info[0] > 2 :
    return input(strPrompt)
  else:
    print("Please upgrade to Python 3")
    sys.exit()

def processConf(strConf_File):

  LogEntry("Looking for configuration file: {}".format(strConf_File))
  if os.path.isfile(strConf_File):
    LogEntry("Configuration File exists")
  else:
    LogEntry("Can't find configuration file {}, make sure it is the same directory "
      "as this script and named the same with ini extension".format(strConf_File))
    objLogOut.close()
    sys.exit(9)

  strLine = "  "
  dictConfig = {}
  LogEntry("Reading in configuration")
  try:
    objINIFile = open(strConf_File,"r")
    strLines = objINIFile.readlines()
    objINIFile.close()
  except PermissionError:
    LogEntry("unable to open configuration file {} for reading or actually reading it, "
      "permission denied.".format(strConf_File),True)
  except Exception as err:
    LogEntry("Unexpected error while attempting to open {} for reading. Error Details: {}".format(strConf_File,err),True)

  for strLine in strLines:
    strFullLine = strLine.strip()
    iCommentLoc = strLine.find("#")
    if iCommentLoc > -1:
      strLine = strFullLine[:iCommentLoc].strip()
    else:
      strLine = strFullLine.strip()
    if "=" in strLine:
      strConfParts = strLine.split("=")
      strLineParts = strFullLine.split("=")
      strVarName = strConfParts[0].strip()
      if "pwd" in strVarName.lower() \
        or "secret" in strVarName.lower() \
        or "key" in strVarName.lower():
          strValue = strLineParts[1].strip()
      else:
        strValue = strConfParts[1].strip()
      dictConfig[strVarName] = strValue
      if strVarName == "include":
        LogEntry("Found include directive: {}".format(strValue))
        strValue = strValue.replace("\\","/")
        if strValue[:1] == "/" or strValue[1:3] == ":/":
          LogEntry("include directive is absolute path, using as is")
        else:
          strValue = strBaseDir + strValue
          LogEntry("include directive is relative path,"
            " appended base directory. {}".format(strValue))
        if os.path.isfile(strValue):
          LogEntry("file is valid")
          try:
            objINIFile = open(strValue,"r")
            strLines += objINIFile.readlines()
          except PermissionError:
            LogEntry("unable to open configuration file {} for reading, "
              "permission denied.".format(strValue),True)
          except Exception as err:
            LogEntry("Unexpected error while attempting to open {} for reading. Error Details: {}".format(strValue,err),True)
          objINIFile.close()
        else:
          LogEntry("invalid file in include directive")

  LogEntry("Done processing configuration, moving on")
  return dictConfig

def CleanExit(strCause):
  try:
    objLogOut.close()
  except:
    pass
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print(strMsg)
  if bAbort:
    CleanExit("")

def isInt(CheckValue):
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

def MakeAPICall(strURL, strHeader, strMethod,  dictPayload=""):

  global tLastCall
  global iTotalSleep
  global strRawResults

  fTemp = time.time()
  fDelta = fTemp - tLastCall
  # LogEntry("It's been {} seconds since last API call".format(fDelta))
  if fDelta > iMinQuiet:
    tLastCall = time.time()
  else:
    iDelta = int(fDelta)
    iAddWait = iMinQuiet - iDelta
    # LogEntry("It has been less than {} seconds since last API call, waiting {} seconds".format(iMinQuiet,iAddWait))
    iTotalSleep += iAddWait
    time.sleep(iAddWait)

  # LogEntry("Doing a {} to URL: {} with payload of '{}'".format(strMethod,strURL,dictPayload))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, verify=False, proxies=dictProxies)
      # LogEntry("get executed")
    if strMethod.lower() == "post":
      if dictPayload != "":
        WebRequest = requests.post(strURL, json= dictPayload, headers=strHeader, verify=False, proxies=dictProxies)
      else:
        WebRequest = requests.post(strURL, headers=strHeader, verify=False, proxies=dictProxies)
      # LogEntry("post executed")
  except Exception as err:
    dictError = {}
    dictError["error"] = "Issue with API call. {}".format(err)
    # LogEntry (dictError,True)
    return dictError

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry("response is unknown type")
    return {"error":"Response is of unknown type"}

  # LogEntry("call resulted in status code {}".format(WebRequest.status_code))
  if WebRequest.status_code != 200:
    LogEntry(WebRequest.text)

  if WebRequest.text[:15].upper() == "<!DOCTYPE HTML>" or WebRequest.text[:6].upper() == "<HTML>":
    LogEntry(WebRequest.text)
    return {"error":"Response was HTML but I need json"}

  strRawResults = WebRequest.text
  if strRawResults == "":
    if WebRequest.status_code == 200:
      return {"Success":"Empty response. Status:200 OK"}
    else:
      return {"error":"Empty response. Status:{}".format(WebRequest.status_code)}

  try:
    return WebRequest.json()
  except Exception as err:
    LogEntry("Exception while converting response to json. Here is what the the response was:'{}'".format(strRawResults))
    dictError = {}
    dictError["error"] = ("Issue with converting response to json. Here is the error detail: {}\n"
          "Here are the first 99 character of the response: {}".format(err,WebRequest.text[:99]))
    return dictError

def main():
  global ISO
  global dictConfig
  global dictPayload
  global iMinQuiet
  global iRowCount
  global iTimeOut
  global iTotalSleep
  global objLogOut
  global strBaseDir
  global strBaseURL
  global strScriptHost
  global strScriptName
  global tLastCall
  global tStart
  global strHeader
  global iMaxRetry
  global dictProxies

  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  iRowCount = 0
  tStart=time.time()

  dictPayload = {}

  strBaseDir = os.path.dirname(sys.argv[0])
  strRealPath = os.path.realpath(sys.argv[0])
  strRealPath = strRealPath.replace("\\","/")
  if strBaseDir == "":
    iLoc = strRealPath.rfind("/")
    strBaseDir = strRealPath[:iLoc]
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
  strLogDir  = strBaseDir + "Logs/"
  strOutDir  = strBaseDir + "json/"
  if strLogDir[-1:] != "/":
    strLogDir += "/"
  if strOutDir[-1:] != "/":
    strOutDir += "/"

  if not os.path.exists(strLogDir) :
    os.makedirs(strLogDir)
    print("Path '{0}' for log files didn't exists, so I create it!".format(strLogDir))

  strScriptName = os.path.basename(sys.argv[0])
  iLoc = strScriptName.rfind(".")
  strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
  strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])

  print("This is a script that uses Tenable API to pause scan jobs that are running, and start those that are paused. "
        "You need specify whether to start of pause as an arugment.\n"
        "This is running under Python Version {}".format(strVersion))
  print("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print("The time now is {}".format(dtNow))
  print("Logs saved to {}".format(strLogFile))
  print("Output files saved to {}".format(strOutDir))
  objLogOut = open(strLogFile,"w",1)

  iLoc = lstSysArg[0].rfind(".")
  strConf_File = lstSysArg[0][:iLoc] + ".ini"
  LogEntry("Setting conf file to: {}".format(strConf_File))

  strScriptHost = platform.node().upper()
  dictConfig = processConf(strConf_File)

  if "AccessKey" in dictConfig and "Secret" in dictConfig:
    strHeader={
      'Content-type':'application/json',
      'X-ApiKeys':'accessKey=' + dictConfig["AccessKey"] + ';secretKey=' + dictConfig["Secret"]}
  else:
    LogEntry("API Keys not provided, exiting.",True)

  if "APIBaseURL" in dictConfig:
    strBaseURL = dictConfig["APIBaseURL"]
  else:
    CleanExit("No Base API provided")
  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  if "TimeOut" in dictConfig:
    if isInt(dictConfig["TimeOut"]):
      iTimeOut = int(dictConfig["TimeOut"])
    else:
      LogEntry("Invalid timeout, setting to defaults of {}".format(iTimeOut))

  if "MinQuiet" in dictConfig:
    if isInt(dictConfig["MinQuiet"]):
      iMinQuiet = int(dictConfig["MinQuiet"])
    else:
      LogEntry("Invalid MinQuiet, setting to defaults of {}".format(iMinQuiet))

  if "MaxError" in dictConfig:
    if isInt(dictConfig["MaxError"]):
      iMaxRetry = int(dictConfig["MaxError"])
    else:
      LogEntry("Invalid MaxError, setting to defaults of {}".format(iMaxRetry))

  if "Proxies" in dictConfig:
    strProxies = dictConfig["Proxies"]
    dictProxies = {"http":strProxies,"https":strProxies}
  else:
    dictProxies = {}

  if iSysArgLen > 1:
    strFunction = lstSysArg[1]
  else:
    LogEntry("No command provided. Use parameter resume or pause to indicate desired function",True)
  
  LogEntry("Got command of {}".format(strFunction))

  dictStatus = {}
  dictStatus["resume"] = "paused"
  dictStatus["pause"] = "running"

  if strFunction.lower() == "resume" or strFunction.lower() == "pause":
    strFunction = strFunction.lower()
  else:
    LogEntry("Only resume and pause are valid options.",True)
    
  strURL = strBaseURL + "scans"
  APIResponse = MakeAPICall(strURL,strHeader,"get",dictPayload)
  if isinstance(APIResponse,dict):
    if "scans" in APIResponse:
      if isinstance(APIResponse["scans"],list):
        for dictScans in APIResponse["scans"]:
          if "name" in dictScans:
            strName = dictScans["name"]
          else:
            strName = "with no name"
          if "id" in dictScans:
            strID = str(dictScans["id"])
            strURL = strBaseURL + "scans/" + strID + "/" + strFunction
          else:
            continue
          if "type" in dictScans:
            if dictScans["type"] != "":
              if "status" in dictScans:
                if dictScans["status"] == dictStatus[strFunction]:
                  LogEntry("Job {} state: {}. Issuing {} command".format(strName,dictScans["status"],strFunction))
                  APIResponse = MakeAPICall(strURL,strHeader,"post",dictPayload)
                  LogEntry(APIResponse)
                else:
                  LogEntry("Job {} state: {}. Doing Nothing".format(strName,dictScans["status"]))
              else:
                LogEntry("No status")
            else:
              LogEntry("Blank Type")
          else:
            LogEntry("No Type")
      else:
        LogEntry("Scan branch is not a list")
    else:
      LogEntry("No scan branch")
  else:
    LogEntry("API Response not a dict")

  LogEntry ("Done")

if __name__ == '__main__':
  main()
