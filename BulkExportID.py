'''
Tenable PluginID Export API Script
Author Siggi Bjarnason Copyright 2020

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
iChunkSize = 5000
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
iTotalSleep = 0
tLastCall = 0

def processConf(strConf_File):

  LogEntry ("Looking for configuration file: {}".format(strConf_File))
  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, make sure it is the same directory "
      "as this script and named the same with ini extension".format(strConf_File))
    LogEntry("{} on {}: Exiting.".format (strScriptName,strScriptHost))
    objLogOut.close()
    sys.exit(9)

  strLine = "  "
  dictConfig = {}
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
      dictConfig[strVarName] = strValue
      if strVarName == "include":
        LogEntry ("Found include directive: {}".format(strValue))
        strValue = strValue.replace("\\","/")
        if strValue[:1] == "/" or strValue[1:3] == ":/":
          LogEntry("include directive is absolute path, using as is")
        else:
          strValue = strBaseDir + strValue
          LogEntry("include directive is relative path,"
            " appended base directory. {}".format(strValue))
        if os.path.isfile(strValue):
          LogEntry ("file is valid")
          objINIFile = open(strValue,"r")
          strLines += objINIFile.readlines()
          objINIFile.close()
        else:
          LogEntry ("invalid file in include directive")

  LogEntry ("Done processing configuration, moving on")
  return dictConfig

def SendNotification (strMsg):
  if True:
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
  #dtNow = time.asctime()
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

def main():
  global ISO
  global bNotifyEnabled
  global dictConfig
  global dictPayload
  global iLimit
  global iLoc
  global iMinQuiet
  global iRowCount
  global iTimeOut
  global iTotalSleep
  global objFileOut
  global objLogOut
  global strBaseDir
  global strBaseURL
  global strFileout
  global strFormat
  global strNotifyChannel
  global strNotifyToken
  global strNotifyURL
  global strOutDir
  global strScriptHost
  global strScriptName
  global tLastCall
  global tStart
  global strHeader
  global dictChunkStatus

  strNotifyToken = None
  strNotifyChannel = None
  strNotifyURL = None
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  objFileOut = None
  iRowCount = 0
  tStart=time.time()

  dictChunkStatus = {}
  dictFilter = {}
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
  
  iLoc = sys.argv[0].rfind(".")
  strConf_File = sys.argv[0][:iLoc] + ".ini"

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
  strScriptHost = platform.node().upper()

  print ("This is a script to download Tenable information for a specific PluginID via API. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  print ("Output files saved to {}".format(strOutDir))
  objLogOut = open(strLogFile,"w",1)
  
  dictConfig = processConf(strConf_File)

  if "Filter" in dictConfig:
    lstStrParts = dictConfig["Filter"].split(":")
    for strFilter in lstStrParts:
      lstFilterParts = strFilter.split("|")
      if isInt(lstFilterParts[1]):
        dictFilter[lstFilterParts[0]] = int(lstFilterParts[1])
      elif lstFilterParts[1][0]=="[":
        lstTmp = lstFilterParts[1][1:-1].split(",")
        lstClean = []
        for strTemp in lstTmp:
          if isInt(strTemp):
            lstClean.append(int(strTemp))
          else:
            lstClean.append(strTemp)
        dictFilter[lstFilterParts[0]] = lstClean
      else:
        dictFilter[lstFilterParts[0]] = lstFilterParts[1]
    LogEntry ("Found filter:{}".format(dictFilter))
  
  if "AccessKey" in dictConfig and "Secret" in dictConfig:
    strHeader={
      'Content-type':'application/json',
      'X-ApiKeys':'accessKey=' + dictConfig["AccessKey"] + ';secretKey=' + dictConfig["Secret"]}
  else:
    LogEntry("API Keys not provided, exiting.",True)

  if "NotifyToken" in dictConfig and "NotifyChannel" in dictConfig and "NotificationURL" in dictConfig:
    bNotifyEnabled = True
  else:
    bNotifyEnabled = False
    LogEntry("Missing configuration items for Slack notifications, "
      "turning slack notifications off")

  if "Limit" in dictConfig:
    if isInt(dictConfig["Limit"]):
      iLimit = int(dictConfig["Limit"])
    else:
      LogEntry("Invalid limit, setting to defaults of {}".format(iLimit))
  else:
    LogEntry("No limit provided, setting to defaults of {}".format(iLimit))

  if "APIBaseURL" in dictConfig:
    strBaseURL = dictConfig["APIBaseURL"]
  else:
    CleanExit("No Base API provided")
  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  if "NotifyEnabled" in dictConfig:
    if dictConfig["NotifyEnabled"].lower() == "yes" \
      or dictConfig["NotifyEnabled"].lower() == "true":
      bNotifyEnabled = True
    else:
      bNotifyEnabled = False
  if "DateTimeFormat" in dictConfig:
    strFormat = dictConfig["DateTimeFormat"]
  if "OutFile" in dictConfig:
    strFileout = dictConfig["OutFile"]

  if "TimeOut" in dictConfig:
    if isInt(dictConfig["TimeOut"]):
      iTimeOut = int(dictConfig["TimeOut"])
    else:
      LogEntry("Invalid timeout, setting to defaults of {}".format(iTimeOut))

  if "SecondsBeetweenChecks" in dictConfig:
    if isInt(dictConfig["SecondsBeetweenChecks"]):
      iSecSleep = int(dictConfig["SecondsBeetweenChecks"])
    else:
      LogEntry("Invalid sleep time, setting to defaults of {}".format(iSecSleep))


  if "MinQuiet" in dictConfig:
    if isInt(dictConfig["MinQuiet"]):
      iMinQuiet = int(dictConfig["MinQuiet"])
    else:
      LogEntry("Invalid MinQuiet, setting to defaults of {}".format(iMinQuiet))

  if strFileout is None or strFileout =="":
    LogEntry("outfile not define, using defaults")
    strFileout = strOutDir + strScriptName[:iLoc] + "-" + ISO + ".csv"
  else:
    if not os.path.exists(os.path.dirname(strFileout)):
      LogEntry ("\nPath '{0}' for output files didn't exists, "
        "so I'm creating it!\n".format(strFileout))
      os.makedirs(os.path.dirname(strFileout))
  LogEntry ("Output will be written to {}".format(strFileout))

  try:
    objFileOut = open(strFileout,"w")
  except PermissionError:
    LogEntry("unable to open output file {} for writing, "
      "permission denied.".format(strFileout),True)

  dictPayload["num_assets"] = iChunkSize
  dictPayload["filters"] = dictFilter

  dictResults={}
  dictResults = BulkExport ("vulns")

  LogEntry ("Completed processing, here are the stats:")
  LogEntry ("Downloaded {} vulns".format(dictResults["RowCount"]))
  LogEntry ("Took {0:.2f} seconds to complete, which is {1} hours, {2} minutes and {3:.2f} seconds.".format(
    dictResults["Elapse"],int(dictResults["hours"]),
    int(dictResults["min"]),dictResults["Sec"]))

  LogEntry ("Completed at {}".format(dtNow))
  # SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
  objLogOut.close()


if __name__ == '__main__':
  main()
