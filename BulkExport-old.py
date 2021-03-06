'''
Tenable Host Export API Script
Author Siggi Bjarnason Copyright 2017
Website http://www.ipcalc.us/ and http://www.icecomputing.com

Following packages need to be installed as administrator
pip install requests
pip install jason

'''
# Import libraries
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
# lstFunctions = ["assets","vulns"]
lstFunctions = ["assets"]
iChunkSize = 5000
dictFilter = {}
# dictFilter["has_plugin_results"] = True
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
iLoc = sys.argv[0].rfind(".")

# strConf_File = sys.argv[0][:iLoc] + ".ini"
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
strConf_File = strBaseDir + "TenableConfig.ini"

if not os.path.exists (strLogDir) :
  os.makedirs(strLogDir)
  print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))
if not os.path.exists (strOutDir) :
  os.makedirs(strOutDir)
  print ("\nPath '{0}' for output files didn't exists, so I create it!\n".format(strOutDir))


strScriptName = os.path.basename(sys.argv[0])
iLoc = strScriptName.rfind(".")
strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
localtime = time.localtime(time.time())
gmt_time = time.gmtime()
iGMTOffset = (time.mktime(localtime) - time.mktime(gmt_time))/3600
dictPayload = {}
dictPayload["chunk_size"] = iChunkSize
dictPayload["filters"] = dictFilter
strScriptHost = platform.node().upper()
if strScriptHost == "DEV-APS-RHEL-STD-A":
  strScriptHost = "VMSAWS01"

print ("This is a script to download Tenable host information via API. This is running under Python Version {}".format(strVersion))
print ("Running from: {}".format(strRealPath))
dtNow = time.asctime()
print ("The time now is {}".format(dtNow))
print ("Logs saved to {}".format(strLogFile))
print ("Output files saved to {}".format(strOutDir))
objLogOut = open(strLogFile,"w",1)
objFileOut = None

tLastCall = 0
iRowCount = 0
iTotalSleep = 0
tStart=time.time()
dictChunkStatus = {}
bNotifyEnable = False

def SendNotification (strMsg):

  if not bNotifyEnable:
    return
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  dictNotify = {}
  dictNotify["token"] = strNotifyToken
  dictNotify["channel"] = strNotifyChannel
  dictNotify["text"]=strMsg[:199]
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = strNotifyURL + "?" + strNotifyParams
  bStatus = False
  try:
    WebRequest = requests.get(strURL,timeout=iTimeOut)
  except Exception as err:
    LogEntry ("Issue with sending notifications. {}".format(err))
  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
  else:
    dictResponse = json.loads(WebRequest.text)
    if isinstance(dictResponse,dict):
      if "ok" in dictResponse:
        bStatus = dictResponse["ok"]
        LogEntry ("Successfully sent slack notification\n{} ".format(strMsg))
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Problme: Status Code:[] API Response OK={}")
      LogEntry (WebRequest.text)

def CleanExit(strCause):
  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  objFileOut.close()
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    SendNotification("{} on {}: {}".format (strScriptName,strScriptHost,strMsg[:99]))
    CleanExit("")

def processConf():
  global strBaseURL
  global strUserName
  global strPWD
  global strNotifyURL
  global strNotifyToken
  global strNotifyChannel
  global strHeader

  LogEntry ("Looking for configuration file: {}".format(strConf_File))
  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, make sure it is the same directory as this script".format(strConf_File))
    LogEntry("{} on {}: Exiting.".format (strScriptName,strScriptHost))
    objLogOut.close()
    sys.exit(9)

  strLine = "  "
  LogEntry ("Reading in configuration")
  objINIFile = open(strConf_File,"r")
  strLines = objINIFile.readlines()
  objINIFile.close()

  for strLine in strLines:
    strLine = strLine.strip()
    iCommentLoc = strLine.find("#")
    if iCommentLoc > -1:
      strLine = strLine[:iCommentLoc].strip()
    else:
      strLine = strLine.strip()
    if "=" in strLine:
      strConfParts = strLine.split("=")
      strVarName = strConfParts[0].strip()
      strValue = strConfParts[1].strip()
      strConfParts = strLine.split("=")
      if strVarName == "APIBaseURL":
        strBaseURL = strValue
      if strVarName == "AccessKey":
        strUserName = strValue
      if strVarName == "Secret":
        strPWD = strValue
      if strVarName == "NotificationURL":
        strNotifyURL = strValue
      if strVarName == "NotifyChannel":
        strNotifyChannel = strValue
      if strVarName == "NotifyToken":
        strNotifyToken = strValue
  strHeader={'Content-type':'application/json','X-ApiKeys':'accessKey='+strUserName+';secretKey='+strPWD}

  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  LogEntry ("Done processing configuration, moving on")

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

def ConvertFloat (fValue):
  if isinstance(fValue,(float,int,str)):
    try:
      fTemp = float(fValue)
    except ValueError:
      fTemp = "NULL"
  else:
    fTemp = "NULL"
  return fTemp

def QDate2DB(strDate):
  strTemp = strDate.replace("T"," ")
  return strTemp.replace("Z","")

def DBClean(strText):
  if strText is None:
    return ""
  strTemp = strText.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\"")
  return strTemp

def MakeAPICall (strURL, strHeader, strMethod,  dictPayload=""):

  global tLastCall
  global iTotalSleep

  fTemp = time.time()
  fDelta = fTemp - tLastCall
  LogEntry ("It's been {} seconds since last API call".format(fDelta))
  if fDelta > iMinQuiet:
    tLastCall = time.time()
  else:
    iDelta = int(fDelta)
    iAddWait = iMinQuiet - iDelta
    LogEntry ("It has been less than {} seconds since last API call, waiting {} seconds".format(iMinQuiet,iAddWait))
    iTotalSleep += iAddWait
    time.sleep(iAddWait)
  iErrCode = ""
  iErrText = ""

  LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, verify=False)
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      if dictPayload != "":
        WebRequest = requests.post(strURL, json= dictPayload, headers=strHeader, verify=False)
      else:
        WebRequest = requests.post(strURL, headers=strHeader, verify=False)
      LogEntry ("post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit ("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
  if WebRequest.status_code != 200:
    LogEntry (WebRequest.text)
    iErrCode = WebRequest.status_code
    iErrText = WebRequest.text

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    try:
      return WebRequest.json()
    except Exception as err:
      LogEntry ("Issue with converting response to json. Here are the first 99 character of the response: {}".format(WebRequest.text[:99]))

def FetchChunks(strFunction,lstChunks, strExportUUID):

  global iRowCount
  global dictChunkStatus

  strAPIFunction = strFunction + "/export/"

  for iChunkID in lstChunks:
    if iChunkID in dictChunkStatus:
      LogEntry  ("Already processed chunk # {}, skipping".format(iChunkID))
      continue

    strURL = strBaseURL + strAPIFunction + strExportUUID + "/chunks/" + str(iChunkID)
    APIResponse = MakeAPICall(strURL,strHeader,"get")
    # APIResponse = APIResponse.encode("ascii","ignore")
    # APIResponse = APIResponse.decode("ascii","ignore")
    try:
      objFileOut.write ("{}".format(APIResponse))
    except Exception as err:
      LogEntry ("Issue with writing chunk to file. {}".format(err))
    if isinstance(APIResponse,str):
      LogEntry(APIResponse,True)
      break
    elif isinstance(APIResponse,dict):
      LogEntry ("response is a dict")
    elif isinstance(APIResponse,list):
      iChunkLen = len(APIResponse)
      iRowCount += iChunkLen
      dictChunkStatus[iChunkID] = iChunkLen
      LogEntry  ("Downloaded {0} {1} for chunk {2}. Total {3} {1} downloaded so far.".format(iChunkLen, strFunction, iChunkID,iRowCount))


def BulkExport(strFunction):

  global objFileOut
  global iRowCount

  iRowCount = 0
  iTotalSleep = 0
  tStart=time.time()
  dictResults = {}

  strRAWout = strOutDir + strScriptName[:iLoc] + "-" + strFunction + ISO + ".json"
  objFileOut = open(strRAWout,"w")

  strAPIFunction = strFunction + "/export/"

  strStatus = "PROCESSING"
  iChunkCount = 0
  lstChunks = []

  # Set the payload to the maximum number to be pulled at once

  strURL = strBaseURL + strAPIFunction

  APIResponse = MakeAPICall(strURL,strHeader,"post", dictPayload)
  if isinstance(APIResponse,str):
    LogEntry(APIResponse,True)
  elif isinstance(APIResponse,dict):
    strExportUUID = APIResponse['export_uuid']
    LogEntry ("Export successfully requested. Confirmation UUID {}".format(strExportUUID))
    strURL = strBaseURL + strAPIFunction + strExportUUID + "/status"
    while strStatus == "PROCESSING":
      APIResponse = MakeAPICall(strURL,strHeader,"get")
      if isinstance(APIResponse,str):
        LogEntry(APIResponse,True)
        strStatus = "Error"
      elif isinstance(APIResponse,dict):
        if "status" in APIResponse:
          strStatus = APIResponse["status"]
        else:
          strStatus = "unknown"
        if "chunks_available" in APIResponse:
          if isinstance(APIResponse["chunks_available"],list):
            iChunkCount = len(APIResponse["chunks_available"])
            lstChunks = APIResponse["chunks_available"]
          else:
            LogEntry ("chunks_available is a {}".format(APIResponse["chunks_available"]))
        else:
          LogEntry ("Somethings wrong, 'chunks_available not in response")
        LogEntry ("Status: {} \nChunks Available: {}\n{}\nFetching them".format(strStatus,iChunkCount,lstChunks))
        FetchChunks(strFunction,lstChunks,strExportUUID)
        # if strFunction == "vulns":
        #   exit()
  LogEntry ("Downloaded {} {}".format(iRowCount,strFunction))
  tStop = time.time()
  iElapseSec = tStop - tStart - iTotalSleep
  iMin, iSec = divmod(iElapseSec, 60)
  iHours, iMin = divmod(iMin, 60)
  dictResults["RowCount"]=iRowCount
  dictResults["Elapse"]=iElapseSec
  dictResults["Sec"]=iSec
  dictResults["min"]=iMin
  dictResults["hours"]=iHours
  objFileOut.close()
  return dictResults


processConf()
dictResults={}
for strfunc in lstFunctions:
  dictResults[strfunc] = BulkExport(strfunc)

LogEntry ("Completed processing, here are the stats:")
for strFunction in dictResults:
  LogEntry ("Downloaded {} {}".format(dictResults[strFunction]["RowCount"],strFunction))
  LogEntry ("Took {0:.2f} seconds to complete, which is {1} hours, {2} minutes and {3:.2f} seconds.".format(
    dictResults[strFunction]["Elapse"],int(dictResults[strFunction]["hours"]),
    int(dictResults[strFunction]["min"]),dictResults[strFunction]["Sec"]))

LogEntry ("Completed at {}".format(dtNow))
SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
objLogOut.close()

