'''
Tenable Export API Script
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

def processConf(strConf_File):

  LogEntry ("Looking for configuration file: {}".format(strConf_File))
  if os.path.isfile(strConf_File):
    LogEntry ("Configuration File exists")
  else:
    LogEntry ("Can't find configuration file {}, make sure it is the same directory "
      "as this script and named the same with ini extension".format(strConf_File))
    objLogOut.close()
    sys.exit(9)

  strLine = "  "
  dictConfig = {}
  LogEntry ("Reading in configuration")
  objINIFile = open(strConf_File,"r")
  strLines = objINIFile.readlines()
  objINIFile.close()

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
  if not bNotifyEnabled:
    LogEntry ("Notification not enabled")
    return
  dictNotify = {}
  dictNotify["token"] = dictConfig["NotifyToken"]
  dictNotify["channel"] = dictConfig["NotifyChannel"]
  dictNotify["text"]=strMsg[:iSlackLimit]
  strNotifyParams = urlparse.urlencode(dictNotify)
  strURL = dictConfig["NotificationURL"] + "?" + strNotifyParams
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
  try:
    objLogOut.close()
    objFileOut.close()
  except:
    pass
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

def CSVClean(strText,iLimit):
  if strText is None:
    return ""
  else:
    strTemp = strText.encode("ascii", "ignore")
    strTemp = strTemp.decode("ascii", "ignore")
    strTemp = strTemp.replace(",", " ")
    return strTemp[:iLimit]

def MakeAPICall (strURL, strHeader, strMethod,  dictPayload=""):

  global tLastCall
  global iTotalSleep
  global strRawResults

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

  LogEntry ("Doing a {} to URL: {} with payload of '{}'".format(strMethod,strURL,dictPayload))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, verify=False, proxies=dictProxies)
      LogEntry ("get executed")
    if strMethod.lower() == "post":
      if dictPayload != "":
        WebRequest = requests.post(strURL, json= dictPayload, headers=strHeader, verify=False, proxies=dictProxies)
      else:
        WebRequest = requests.post(strURL, headers=strHeader, verify=False, proxies=dictProxies)
      LogEntry ("post executed")
  except Exception as err:
    return "Issue with API call. {}".format(err)
    # CleanExit ("due to issue with API, please check the logs")

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
  if WebRequest.status_code != 200:
    LogEntry (WebRequest.text)
    iErrCode = WebRequest.status_code
    iErrText = WebRequest.text

  if WebRequest.text[:15].upper() == "<!DOCTYPE HTML>" or WebRequest.text[:6].upper() == "<HTML>":
    return "ERROR: Response was HTML but I need json"
  
  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    strRawResults = WebRequest.text
    try:
      return WebRequest.json()
    except Exception as err:
      return "Issue with converting response to json. Here are the first 99 character of the response: {}".format(WebRequest.text[:99])

def FetchChunks(strFunction,lstChunks, strExportUUID):

  global iRowCount
  global dictChunkStatus
  global iErrCount

  strAPIFunction = strFunction + "/export/"

  for iChunkID in lstChunks:
    if iChunkID in dictChunkStatus:
      LogEntry  ("Already processed chunk # {}, skipping".format(iChunkID))
      continue

    LogEntry("Fetching chunk #{} out of {}".format(iChunkID,strTotalChunks))
    strURL = strBaseURL + strAPIFunction + strExportUUID + "/chunks/" + str(iChunkID)
    APIResponse = MakeAPICall(strURL,strHeader,"get")
    if isinstance(APIResponse,str):
      LogEntry("FetchChunks: " + APIResponse)
      strCond = "err"
      while strCond == "err":
        APIResponse = MakeAPICall(strURL,strHeader,"get")
        if isinstance(APIResponse,str):
          LogEntry("FetchChunks Retry #{}: {}".format(iErrCount, APIResponse))
          strCond = "err"
          iErrCount += 1
          if iErrCount > iMaxRetry:
            LogEntry("Too many fetchchunks errors, exiting",True)
        else:
          LogEntry("FetchChunk Retry Good")
          strCond = "good"
          iErrCount = 0
    if isinstance(APIResponse,dict):
      LogEntry ("response is a dict")
    elif isinstance(APIResponse,list):
      strResponse = "{}".format(strRawResults)
      strResponse = strResponse.encode("ascii","ignore")
      strResponse = strResponse.decode("ascii","ignore")
      strResponse = strResponse[1:-1]
      if iRowCount > 0:
        strResponse = "," + strResponse
      try:
        objFileOut.write ("{}".format(strResponse))
      except Exception as err:
        LogEntry ("Issue with writing chunk to file. {}".format(err))
      iChunkLen = len(APIResponse)
      iRowCount += iChunkLen
      dictChunkStatus[iChunkID] = iChunkLen
      LogEntry  ("Downloaded {0} {1} for chunk {2}. Total {3} {1} downloaded so far.".format(iChunkLen, strFunction, iChunkID,iRowCount))
      for dictChunkItem in APIResponse:
        if strFunction == "assets":
          if "id" in dictChunkItem:
            strAssetID = CSVClean(dictChunkItem["id"],50) 
          else:
            strAssetID = ""
          if "ipv4s" in dictChunkItem:
            strIPv4 = CSVClean (" | ".join(dictChunkItem["ipv4s"]),990)
          else:
            strIPv4 = ""
          if "ipv6s" in dictChunkItem:
            strIPv6 = CSVClean (" | ".join(dictChunkItem["ipv6s"]),990)
          else:
            strIPv6 = ""
          if "fqdns" in dictChunkItem:
            strFQDNs = CSVClean (" | ".join(dictChunkItem["fqdns"]),990)
          else:
            strFQDNs = ""
          if "netbios_names" in dictChunkItem:
            strNetBIOS = CSVClean (" | ".join(dictChunkItem["netbios_names"]),990)
          else:
            strNetBIOS = ""
          if "operating_systems" in dictChunkItem:
            strOS = CSVClean (" | ".join(dictChunkItem["operating_systems"]),990)
          else:
            strOS = ""
          if "hostnames" in dictChunkItem:
            strHostName = CSVClean (" | ".join(dictChunkItem["hostnames"]),990)
          else:
            strHostName = ""
          objCSVOut.write("{},{},{},{},{},{},{}\n".format(strAssetID,strHostName,strFQDNs,strNetBIOS,strIPv4,strIPv6,strOS))
        if strFunction == "vulns":
          if "asset" in dictChunkItem:
            if "uuid" in dictChunkItem["asset"]:
              strAssetID = CSVClean(dictChunkItem["asset"]["uuid"],50) 
            else:
              strAssetID = ""
            if "ipv4" in dictChunkItem["asset"]:
              strIPv4 = CSVClean (dictChunkItem["asset"]["ipv4"],990)
            else:
              strIPv4 = ""
            if "fqdns" in dictChunkItem["asset"]:
              strFQDN = CSVClean (dictChunkItem["asset"]["fqdns"],990)
            else:
              strFQDN = ""
            if "netbios_name" in dictChunkItem["asset"]:
              strNetBIOS = CSVClean (dictChunkItem["asset"]["netbios_name"],990)
            else:
              strNetBIOS = ""
            if "operating_system" in dictChunkItem["asset"]:
              strOS = CSVClean (" | ".join(dictChunkItem["asset"]["operating_system"]),990)
            else:
              strOS = ""
            if "hostname" in dictChunkItem["asset"]:
              strHostName = CSVClean (dictChunkItem["asset"]["hostname"],990)
            else:
              strHostName = ""
            if "network_id" in dictChunkItem["asset"]:
              strNetworkID = dictChunkItem["asset"]["network_id"]
              if strNetworkID == "00000000-0000-0000-0000-000000000000":
                strNetworkName = "Magenta"
              elif strNetworkID == "99357713-57a9-47dc-8689-3ad618444aab":
                strNetworkName = "Sprint"
              else:
                strNetworkName = "Unknown NetworkID {}".format(strNetworkID)
            else:
              strNetworkName = ""
            objCSVOut.write("{},{},{},{},{},{},{},".format(strAssetID,strHostName,strFQDN,strNetBIOS,strIPv4,strNetworkName,strOS))
          if "plugin" in dictChunkItem:
            if "id" in dictChunkItem["plugin"]:
              strPluginID = CSVClean(str(dictChunkItem["plugin"]["id"]),50) 
            else:
              strPluginID = ""
            if "name" in dictChunkItem["plugin"]:
              strPluginName = CSVClean (dictChunkItem["plugin"]["name"],990)
            else:
              strPluginName = ""
            if "description" in dictChunkItem["plugin"]:
              strDescr = CSVClean (dictChunkItem["plugin"]["description"],990)
            else:
              strDescr = ""
            if "family" in dictChunkItem["plugin"]:
              strFamilyName = CSVClean (dictChunkItem["plugin"]["family"],990)
            else:
              strFamilyName = ""
            if "family_id" in dictChunkItem["plugin"]:
              strFamilyID = CSVClean (str(dictChunkItem["family_id"]),990)
            else:
              strFamilyID = ""
            objCSVOut.write("{},{},{},{},{}\n".format(strPluginID,strPluginName,strDescr,strFamilyName,strFamilyID))

def BulkExport(strFunction,strExportUUID):
  global iRowCount
  global iErrCount
  global strTotalChunks

  iRowCount = 0
  iTotalSleep = 0
  tStart=time.time()
  dictResults = {}

  strAPIFunction = strFunction + "/export/"

  strStatus = "PROCESSING"
  iChunkCount = 0
  lstChunks = []

  strURL = strBaseURL + strAPIFunction

  strTotalChunks = "n/a"
  if strExportUUID == "":
    APIResponse = MakeAPICall(strURL,strHeader,"post", dictPayload)
    if isinstance(APIResponse,str):
      LogEntry("1stExport: " + APIResponse,True)
    elif isinstance(APIResponse,dict):
      strExportUUID = APIResponse['export_uuid']
      LogEntry ("Export successfully requested. Confirmation UUID {}".format(strExportUUID))
  strURL = strBaseURL + strAPIFunction + "status"
  while strTotalChunks == "n/a":
    LogEntry ("Checking for total number of chunks")
    APIResponse = MakeAPICall(strURL,strHeader,"get")
    if isinstance(APIResponse,str):
      LogEntry("Numbers of Chunks error, attempt #{}: {}".format(iErrCount, APIResponse))
      iErrCount += 1
      if iErrCount > iMaxRetry:
        strTotalChunks = "Error"
        LogEntry("Too many status check errors, moving on")
    elif isinstance(APIResponse,dict):
      iErrCount = 0
      if "exports" in APIResponse:
        if isinstance(APIResponse["exports"],list):
            iListSize = len(APIResponse["exports"])
            LogEntry("there are {} exports in the list".format(iListSize))
            for dictValue in APIResponse["exports"]:
              if dictValue["uuid"] == strExportUUID:
                if "total_chunks" in dictValue:
                  strTotalChunks = dictValue["total_chunks"]
                else:
                  LogEntry ("Total Chunks not available, trying again")
                if strTotalChunks == 0:
                  strTotalChunks = "n/a"
                  LogEntry ("Total Chunks is zero, trying again.")
                break
                
  LogEntry("Total Chunks: {}".format(strTotalChunks))
  strURL = strBaseURL + strAPIFunction + strExportUUID + "/status"
  while strStatus == "PROCESSING":
    APIResponse = MakeAPICall(strURL,strHeader,"get")
    if isinstance(APIResponse,str):
      LogEntry("Status check error, attempt #{}: {}".format(iErrCount, APIResponse))
      iErrCount += 1
      if iErrCount > iMaxRetry:
        strStatus = "Error"
        LogEntry("Too many status check errors, finishing up")
    elif isinstance(APIResponse,dict):
      iErrCount = 0
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
      LogEntry ("Status: {} | Chunks Available: {} out of {}".format(strStatus,iChunkCount,strTotalChunks))
      if iChunkCount > 0:
        LogEntry ("Available Chunks: {}".format(lstChunks))
        lstNotProcessed = []
        for iChunkID in lstChunks:
          if iChunkID not in dictChunkStatus:
            lstNotProcessed.append(iChunkID)
        if len(lstNotProcessed) > 0:
          LogEntry("Now fetching chunks {}".format(lstNotProcessed))
          FetchChunks(strFunction,lstNotProcessed,strExportUUID)
  LogEntry("Final status {}".format(strStatus))
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
  return dictResults

def main():
  global ISO
  global bNotifyEnabled
  global dictConfig
  global dictPayload
  global iMinQuiet
  global iRowCount
  global iTimeOut
  global iTotalSleep
  global objFileOut
  global objLogOut
  global strBaseDir
  global strBaseURL
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
  global iChunkSize
  global objFileOut
  global objCSVOut
  global iMaxRetry
  global dictProxies
  global iSlackLimit

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
  
  if not os.path.exists (strLogDir) :
    os.makedirs(strLogDir)
    print ("Path '{0}' for log files didn't exists, so I create it!".format(strLogDir))
  if not os.path.exists (strOutDir) :
    os.makedirs(strOutDir)
    print ("Path '{0}' for output files didn't exists, so I create it!".format(strOutDir))

  strScriptName = os.path.basename(sys.argv[0])
  iLoc = strScriptName.rfind(".")
  strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
  strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])

  print ("This is a script to download Tenable information for a specific PluginID via API. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  print ("Output files saved to {}".format(strOutDir))
  objLogOut = open(strLogFile,"w",1)
  iConfLoc = 0
  iUUIDLoc = 0
  iPos = 0
  
  if iSysArgLen > 1:
    for strArg in lstSysArg:
      if iPos == 0:
        iPos += 1
        # LogEntry ("skipping first strArg")
        continue
      if strArg[-4:] == ".ini":
        iConfLoc = iPos
        LogEntry ("Found configuration file in command arguments pos {}".format(iPos))
      elif "-" in strArg:
        iUUIDLoc = iPos
        LogEntry ("Found UUID in command line arugment pos {}".format(iPos))
      else:
        LogEntry ("unknown argument {} in pos {}. Expect either UUID like e1e742b0-b10c-4f58-931e-568327d62291" 
                  "or configuration file with .ini extension".format(strArg,iPos))
      iPos += 1
  if iConfLoc > 0:
    strConf_File = lstSysArg[iConfLoc]
    LogEntry("Argument provided, setting conf file to: {}".format(strConf_File))
  else:
    iLoc = lstSysArg[0].rfind(".")
    strConf_File = lstSysArg[0][:iLoc] + ".ini"
    LogEntry("No Argument found, setting conf file to: {}".format(strConf_File))

  strScriptHost = platform.node().upper()
  dictConfig = processConf(strConf_File)
  if strScriptHost in dictConfig:
    strScriptHost = dictConfig[strScriptHost]
  LogEntry ("Starting {} on {}".format(strScriptName,strScriptHost))
  
  if "Filter" in dictConfig:
    lstStrParts = dictConfig["Filter"].split(":")
    for strFilter in lstStrParts:
      lstFilterParts = strFilter.split("|")
      if len(lstFilterParts) > 1:
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

  if "TextLimit" in dictConfig:
    if isInt(dictConfig["TextLimit"]):
      iSlackLimit = int(dictConfig["TextLimit"])
    else:
      LogEntry("Invalid TextLimit, setting to defaults of {}".format(iSlackLimit))

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
  
  if "TimeStampDefOutFile" in dictConfig:
    if dictConfig["TimeStampDefOutFile"].lower() == "yes" \
      or dictConfig["TimeStampDefOutFile"].lower() == "true":
      bTimeFile = True
    else:
      bTimeFile = False

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

  if "BatchSize" in dictConfig:
    if isInt(dictConfig["BatchSize"]):
      iChunkSize = int(dictConfig["BatchSize"])
    else:
      LogEntry("Invalid MinQuiet, setting to defaults of {}".format(iChunkSize))

  if "MaxError" in dictConfig:
    if isInt(dictConfig["MaxError"]):
      iMaxRetry = int(dictConfig["MaxError"])
    else:
      LogEntry("Invalid MinQuiet, setting to defaults of {}".format(iMaxRetry))

  if "UpdatedDays" in dictConfig:
    LogEntry("Found Update Days")
    if isInt(dictConfig["UpdatedDays"]):
      iLastDays = int(dictConfig["UpdatedDays"])
      LogEntry("it's a valid int, calculating")
      tupDate = datetime.today() - timedelta(days=iLastDays)
      iUpdateSince = int(datetime.timestamp(tupDate))
      dictFilter["updated_at"] = iUpdateSince
    else:
      LogEntry("Not a valid int '{}'".format(dictConfig["UpdatedDays"]))

  if "ExportType" in dictConfig:
    strExportType = dictConfig["ExportType"]
  else:
    LogEntry("Export Type not defined in configuration file, aborting",True)

  if "Proxies" in dictConfig:
    strProxies = dictConfig["Proxies"]
    dictProxies = {"http":strProxies,"https":strProxies}
  else:
    dictProxies = {}

  if "OutFile" in dictConfig:
    strRAWout = dictConfig["OutFile"]
  else:
    if bTimeFile:
      strRAWout = strOutDir + strScriptName[:iLoc] + "-" + strExportType + ISO + ".json"
    else:
      strRAWout = strOutDir + strScriptName[:iLoc] + "-" + strExportType + ".json"
  
  try:
    objFileOut = open(strRAWout,"w")
    objFileOut.write("[")
  except PermissionError:
    LogEntry("unable to open output file {} for writing, "
      "permission denied.".format(strRAWout),True)
  LogEntry ("Raw Output file {} created".format(strRAWout))

  iExtLoc = strRAWout.rfind(".")
  strCSVName = strRAWout[:iExtLoc] + ".csv"
  objCSVOut = open(strCSVName,"w",1)
  objCSVOut.write("AssetID,HostName,DNS,NetBIOS,IPv4,IPv6,OS\n")

  if strExportType == "vulns":
    dictPayload["num_assets"] = iChunkSize
  if strExportType == "assets":
    dictPayload["chunk_size"] = iChunkSize
  dictPayload["filters"] = dictFilter

  if iUUIDLoc > 0:
    strExportUUID = sys.argv[iUUIDLoc]
    LogEntry ("UUID {} provided as an arg".format(strExportUUID))
  else:
    strExportUUID = ""

  # SendNotification ("Starting {} on {}".format(strScriptName, strScriptHost))
  dictResults={}
  dictResults = BulkExport (strExportType,strExportUUID)
  objFileOut.write("]")
  LogEntry ("Completed processing, here are the stats:")
  LogEntry ("Downloaded {} {}".format(dictResults["RowCount"],strExportType))
  LogEntry ("Took {0:.2f} seconds to complete, which is {1} hours, {2} minutes and {3:.2f} seconds.".format(
    dictResults["Elapse"],int(dictResults["hours"]),
    int(dictResults["min"]),dictResults["Sec"]))

  LogEntry ("Completed at {}".format(dtNow))
  LogEntry ("Results save to {}".format(strRAWout))
  SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
  objLogOut.close()
  objFileOut.close()

if __name__ == '__main__':
  main()
