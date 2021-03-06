'''
Tenable API Script to sync Agent Groups to Tags
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
iLineCount = 0
iTotalScan = 0

def formatUnixDate(iDate):
  if iDate > 9999999999:
    iDate = iDate / 1000
  structTime = time.localtime(iDate)
  return time.strftime(strFormat,structTime)

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

def isFloat (CheckValue):
  # function to safely check if a value can be interpreded as an int
  if isinstance(CheckValue,float):
    return True
  elif isinstance(CheckValue,str):
    try:
      fTemp = float(CheckValue)
      if isinstance(fTemp,float):
        return True
      else:
        return False
    except ValueError:
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
  # LogEntry ("It's been {} seconds since last API call".format(fDelta))
  if fDelta > iMinQuiet:
    tLastCall = time.time()
  else:
    iDelta = int(fDelta)
    iAddWait = iMinQuiet - iDelta
    # LogEntry ("It has been less than {} seconds since last API call, waiting {} seconds".format(iMinQuiet,iAddWait))
    iTotalSleep += iAddWait
    time.sleep(iAddWait)
  iErrCode = ""
  iErrText = ""
  WebRequest = None

  # LogEntry ("Doing a {} to URL: \n {}\n with payload of {}".format(strMethod,strURL,dictPayload))
  try:
    if strMethod.lower() == "get":
      WebRequest = requests.get(strURL, headers=strHeader, verify=False)
      # LogEntry ("get executed")
    if strMethod.lower() == "post":
      if dictPayload != "":
        WebRequest = requests.post(strURL, json= dictPayload, headers=strHeader, verify=False)
      else:
        WebRequest = requests.post(strURL, headers=strHeader, verify=False)
      # LogEntry ("post executed")
    if strMethod.lower() == "put":
      if dictPayload != "":
        WebRequest = requests.put(strURL, json= dictPayload, headers=strHeader, verify=False)
      else:
        WebRequest = requests.put(strURL, headers=strHeader, verify=False)
      # LogEntry ("post executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit ("due to issue with API, please check the logs")

  if WebRequest is None:
    LogEntry ("response is none type",True)
    iErrCode = "NoneType"
    iErrText = "response is none type"

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    iErrCode = "ResponseErr"
    iErrText = "response is unknown type"

  # LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
  if WebRequest.status_code != 200:
    iErrCode = WebRequest.status_code
    iErrText = WebRequest.text
    LogEntry ("Doing a {} to URL: {} with payload of '{}' resulted in {} error".format(
      strMethod,strURL,dictPayload,iErrCode))
    LogEntry (WebRequest.text)

  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    try:
      return WebRequest.json()
    except Exception as err:
      LogEntry ("Issue with converting response to json. Here are the first 99 character of the response: {}".format(WebRequest.text[:99]))

def CleanStr(strOld):
  strTemp = strOld.replace('"','')
  strTemp = strTemp.replace(',','')
  strTemp = strTemp.replace('\n','')
  return strTemp.strip()

def GetValues():
  dictAllValues = {}
  dictPayload = {}
  strMethod = "get"
  strAPIFunction = "tags/values"
  strURL = strBaseURL + strAPIFunction
  LogEntry("Pulling a list of existing Tag Values")
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if "values" in APIResponse:
    if isinstance(APIResponse["values"],list):
        for dictValue in APIResponse["values"]:
            strValueID = dictValue["uuid"]
            strValue = dictValue["value"]
            dictAllValues[strValue] = strValueID
    else:
        LogEntry("Values is not a list, no idea what to do with this: {}".format(APIResponse),True)
  else:
    LogEntry ("Unepxected results: {}".format(APIResponse),True)
  return dictAllValues

def GetGroups():
  dictPayload = {}
  strMethod = "get"
  strAPIFunction = "scanners/scanner_id/agent-groups/"
  strURL = strBaseURL + strAPIFunction
  LogEntry("Now Pulling a list of all Agent Groups")
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  dictAllGroups = {}
  if "groups" in APIResponse:
    if isinstance(APIResponse["groups"],list):
      for dictAG in APIResponse["groups"]:
        strID = dictAG["id"]
        strGroupName = dictAG["name"]
        iLastModified = dictAG["last_modification_date"]
        dtLastModified = formatUnixDate(iLastModified)
        LogEntry ("Group {} last updated {} which is {} ".format(strGroupName,iLastModified,dtLastModified))
        if iLastModified > iLastRan:
          LogEntry ("Group has been modified since last run, adding to list")
        else:
          LogEntry ("No change since last run, skipping")
          continue
        if strGroupName == "Default":
          LogEntry ("Skipping the default group")
          continue
        dictAllGroups[strGroupName] = strID
    else:
      LogEntry("No list in groups, can't do anything",True)
  else:
    LogEntry("no group in response, unable to proceed",True)
  return dictAllGroups

def GroupDetails(iGroupID):
  dictPayload = {}
  strMethod = "get"
  lstAssets = []

  strAPIFunction = "scanners/agents/agent-groups/" + str(iGroupID)
  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if "agents" in APIResponse:
    if isinstance(APIResponse["agents"],list):
      for dictAgent in APIResponse["agents"]:
        LogEntry ("{} {}".format(dictAgent["name"],dictAgent["uuid"]))
        lstAssets.append({"id":dictAgent["uuid"],"name":dictAgent["name"]})
    else:
      LogEntry("No list under agents, can not deal",True)
  else:
    LogEntry("No agents in response, no idea what to do",True)
  return lstAssets

def GetAssetID(strHostName):
  dictPayload = {}
  dictParams = {}
  strAssetID = ""

  strMethod = "get"
  dictParams["filter.0.filter"] = "host.target"
  dictParams["filter.0.quality"] = "match"
  dictParams["filter.0.value"] = strHostName
  dictParams["filter.1.filter"] = "fqdn"
  dictParams["filter.1.quality"] = "match"
  dictParams["filter.1.value"] = strHostName
  strParams = urlparse.urlencode(dictParams)

  strAPIFunction = "workbenches/assets"
  strURL = strBaseURL + strAPIFunction + "?" + strParams
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if "assets" in APIResponse:
    if isinstance(APIResponse["assets"],list):
      if len(APIResponse["assets"]) == 0:
        LogEntry("Empty response for {}".format(strHostName))
      for dictAsset in APIResponse["assets"]:
        strAssetID = dictAsset["id"]
        if "has_agent" in dictAsset:
          if dictAsset["has_agent"]:
            LogEntry ("{} Asset ID is {}".format(strHostName,strAssetID))
            continue
          else:
            LogEntry("Instance of {} with ID of {} has no agent".format(strHostName,strAssetID))
        else:
          LogEntry("No 'has_agent'")
    else:
      LogEntry("No list under assets, can not deal",True)
  else:
    LogEntry("No assets in response, no idea what to do",True)
  return strAssetID

def Tenable2AssetID(strTenableID,strHostName):
  dictPayload = {}
  dictParams = {}
  strAssetID = ""

  strTenableID = strTenableID.replace("-","")
  strMethod = "get"
  dictParams["filter.0.filter"] = "tenable_uuid"
  dictParams["filter.0.quality"] = "eq"
  dictParams["filter.0.value"] = strTenableID

  strParams = urlparse.urlencode(dictParams)

  strAPIFunction = "workbenches/assets"
  strURL = strBaseURL + strAPIFunction + "?" + strParams
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if "assets" in APIResponse:
    if isinstance(APIResponse["assets"],list):
      if len(APIResponse["assets"]) == 0:
        LogEntry("Empty response for {}".format(strHostName))
      for dictAsset in APIResponse["assets"]:
        strAssetID = dictAsset["id"]
        LogEntry ("{} Asset ID is {}".format(strHostName,strAssetID))
    else:
      LogEntry("No list under assets, can not deal",True)
  else:
    LogEntry("No assets in response, no idea what to do",True)
  return strAssetID

def CreateTag(strGroupName,iGroupID):
  dictPayload = {}

  dictPayload["category_name"] = "AgentGroups"
  dictPayload["value"] = strGroupName
  dictPayload["description"] = "Created by script from Agent Group ID {}".format(iGroupID)
  strMethod = "post"
  strAPIFunction = "tags/values/"
  strURL = strBaseURL + strAPIFunction
  LogEntry("Submitting request to create")
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if isinstance(APIResponse,dict):
    if "uuid" in APIResponse:
      strTagUUID = APIResponse["uuid"]
      LogEntry("Tag Value created successfully. ID:{}".format(APIResponse["uuid"]))
    else:
      LogEntry("No UUID\n{}".format(APIResponse),True)
  else:
    LogEntry("Response for group {} is not dictionary\n{}".format(strGroupName, APIResponse))
  return strTagUUID

def TagAssets(strTagUUID,lstAssets):
  lstTags = []
  lstTags.append(strTagUUID)
  dictPayload = {}
  dictPayload["action"] = "add"
  dictPayload["assets"] = lstAssets
  dictPayload["tags"] = lstTags
  strMethod = "post"
  strAPIFunction = "tags/assets/assignments/"
  strURL = strBaseURL + strAPIFunction
  LogEntry ("Applying tags by calling {} with payload of {}".format(strURL,dictPayload))
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if isinstance(APIResponse,dict):
    if "job_uuid" in APIResponse:
      LogEntry("Job submitted successfully. Job UUID:{}".format(APIResponse["job_uuid"]))
    else:
      LogEntry("No job UUID\n{}".format(APIResponse))
  else:
    LogEntry("Response is not dictionary\n{}".format(APIResponse))

def main():
  global ISO
  global bNotifyEnabled
  global iMinQuiet
  global iTimeOut
  global iTotalSleep
  global objLogOut
  global strBaseDir
  global strFormat
  global strNotifyChannel
  global strNotifyToken
  global strNotifyURL
  global strScriptHost
  global strScriptName
  global tLastCall
  global tStart
  global strBaseURL
  global strHeader
  global iLastRan

  strNotifyToken = None
  strNotifyChannel = None
  strNotifyURL = None
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  tStart=time.time()

  strBaseDir = os.path.dirname(sys.argv[0])
  strRealPath = os.path.realpath(sys.argv[0])
  strRealPath = strRealPath.replace("\\","/")
  if strBaseDir == "":
    iLoc = strRealPath.rfind("/")
    strBaseDir = strRealPath[:iLoc]
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
  strLogDir  = strBaseDir + "Logs/"
  if strLogDir[-1:] != "/":
    strLogDir += "/"
  
  iLoc = sys.argv[0].rfind(".")
  strConf_File = sys.argv[0][:iLoc] + ".ini"
  strCacheFile = sys.argv[0][:iLoc] + ".cache"

  if not os.path.exists (strLogDir) :
    os.makedirs(strLogDir)
    print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))

  strScriptName = os.path.basename(sys.argv[0])
  iLoc = strScriptName.rfind(".")
  strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
  strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])

  print ("This is a script to sync Agent Group to Tags via API. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)
  
  dictConfig = processConf(strConf_File)

  strScriptHost = platform.node().upper()
  if strScriptHost in dictConfig:
    strScriptHost = dictConfig[strScriptHost]

  LogEntry ("Starting {} on {}".format(strScriptName,strScriptHost))

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
  
  if "DiffOnly" in dictConfig:
    if dictConfig["DiffOnly"].lower() == "yes" \
      or dictConfig["DiffOnly"].lower() == "true":
      bDiffOnly = True
    else:
      bDiffOnly = False

  if "DateTimeFormat" in dictConfig:
    strFormat = dictConfig["DateTimeFormat"]
  else:
    strFormat = ""

  if "FilterCriteria" in dictConfig:
    strFilter = dictConfig["FilterCriteria"]
  else:
    strFilter = ""

  iFilterLen = len(strFilter)

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

  if bDiffOnly:
    if os.path.isfile(strCacheFile):
      objCache = open(strCacheFile,"r")
      strLines = objCache.readline()
      objCache.close()
      if isFloat(strLines):
        iLastRan = float(strLines)
        LogEntry("Found last ran as {} ".format(iLastRan))
      else:
        LogEntry("Last ran time stored as {} which is not a valid floating number, using defaults.".format(strLines))
        iLastRan = 0.0 # defaulting to beginging of time
        # iLastRan = time.time()
        # iLastRan -= 604800 # subtracting 7 days from today as default
    else:
      LogEntry("No last ran time found, using defaults")
      iLastRan = 0.0 # defaulting to beginging of time
      # iLastRan = time.time()
      # iLastRan -= 604800 # subtracting 7 days from today as default
    strOut =str(time.time()) 
  else:
    strOut = "0.0"
    iLastRan = 0.0 # defaulting to beginging of time
  LogEntry("Last ran time set to {} which is {}".format(iLastRan,formatUnixDate(iLastRan)))
  objCache = open(strCacheFile,"w",1)
  objCache.write(strOut)
  objCache.close()
  LogEntry("Saved current time to cache as last ran time")

  dictAllValues = GetValues()
  dictAllGroups = GetGroups()

  lstAssetID = []
  for strGroupName in dictAllGroups.keys():
    if strFilter == "":
      strFilter = strGroupName
      iFilterLen = len(strFilter)
    if strGroupName[:iFilterLen] == strFilter:
      LogEntry("Now Pulling details about group {}".format(strGroupName))
      lstAssets = GroupDetails(dictAllGroups[strGroupName])
      LogEntry("Now getting AssetID for each Asset in the group")
      for dictAsset in lstAssets:
        # lstAssetID.append (GetAssetID(dictAsset["name"]))
        lstAssetID.append (Tenable2AssetID(dictAsset["id"],dictAsset["name"]))

      if strGroupName in dictAllValues:
        strTagUUID = dictAllValues[strGroupName]
        LogEntry ("Tag AgentGroups:{} has UUID {}".format(strGroupName,strTagUUID))
      else:
        LogEntry ("Creating a new value with name and members of the group")
        strTagUUID = CreateTag(strGroupName,dictAllGroups[strGroupName])
      
      TagAssets(strTagUUID,lstAssetID)
    else:
      LogEntry("Group {} does not meet criteria of starts with {} ".format(strGroupName,strFilter))
  LogEntry("Done!")

if __name__ == '__main__':
  main()
