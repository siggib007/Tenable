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

def CleanStr(strOld):
  strTemp = strOld.replace('"','')
  strTemp = strTemp.replace(',','')
  strTemp = strTemp.replace('\n','')
  return strTemp.strip()

def ValidateIP(strToCheck):
	Quads = strToCheck.split(".")
	if len(Quads) != 4:
		return False
	# end if

	for Q in Quads:
		try:
			iQuad = int(Q)
		except ValueError:
			return False
		# end try

		if iQuad > 255 or iQuad < 0:
			return False
		# end if

	return True

def CheckMembers(lstValues):
  lstIPv4 = []
  lstHost = []
  dictReturn = {}
  for strValue in lstValues:
    if strValue.find(":") > 0:
      #Value is an IPv6, unable to process right now
      pass
    elif strValue.find("-") > 0:
      lstValueParts = strValue.split("-")
      if len(lstValueParts) == 2:
        if ValidateIP(lstValueParts[0]) and ValidateIP(lstValueParts[1]):
          lstIPv4.append(strValue.strip())
        else:
          lstHost.append(strValue.strip())
      else:
        lstHost.append(strValue)
    elif strValue.find("/") > 0 and len(strValue) > 6:
      lstValueParts = strValue.split("/")
      bTemp = True
      if len(lstValueParts) != 2:
        bTemp = False
      try:
        iValue = int(lstValueParts[1])
      except ValueError:
        bTemp = False
      if iValue < 1 or iValue > 32:
        bTemp = False
      if not ValidateIP(lstValueParts[0]):
        bTemp = False
      if bTemp:
        lstIPv4.append(strValue.strip())
      else:
        lstHost.append(strValue.strip())
    elif ValidateIP(strValue): 
      lstIPv4.append(strValue.strip())
    else:
      lstHost.append(strValue.strip())
  dictReturn["ipv4"] = ",".join(lstIPv4)
  dictReturn["dns"] = lstHost
  return dictReturn

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

  strNotifyToken = None
  strNotifyChannel = None
  strNotifyURL = None
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  iRowCount = 1
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
  strScriptHost = platform.node().upper()

  print ("This is a script to sync Agent Group to Tags via API. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)
  
  dictConfig = processConf(strConf_File)

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

  if os.path.isfile(strCacheFile):
    objCache = open(strCacheFile,"r")
    strLines = objCache.readline()
    objCache.close()
    if isFloat(strLines):
      iLastRan = float(strLines)
      LogEntry("Found last ran as {} ".format(iLastRan))
    else:
      LogEntry("Last ran time stored as {} which is not a valid int.".format(strLines))
      iLastRan = time.time()
      iLastRan -= 604800 # subtracting 7 days from today as default
  else:
    LogEntry("No last ran time found")
    iLastRan = time.time()
    iLastRan -= 604800 # subtracting 7 days from today as default
  LogEntry("Last ran time set to {} which is {}".format(iLastRan,formatUnixDate(iLastRan)))
  objCache = open(strCacheFile,"w",1)
  objCache.write(str(time.time()))
  objCache.close()
  LogEntry("Saved current time to cache as last ran time")

  dictPayload = {}
  dictAllValues = {}
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
        strName = dictAG["name"]
        iLastModified = dictAG["last_modification_date"]
        dtLastModified = formatUnixDate(iLastModified)
        LogEntry ("Group {} last updated {} which is {} ".format(strName,iLastModified,dtLastModified))
        if iLastModified > iLastRan:
          LogEntry ("Group has been modified since last run")
        else:
          LogEntry ("No change since last run, skipping")
          continue
        if strName == "Default":
          LogEntry ("Skipping the default group")
          continue
        dictAllGroups[strName] = strID
    else:
      LogEntry("No list in groups, can't do anything",True)
  else:
    LogEntry("no group in response, unable to proceed",True)
  
  lstAssets = []
  for strGroupName in dictAllGroups.keys():
    if strFilter == "":
      strFilter = strGroupName
      iFilterLen = len(strFilter)
    if strGroupName[:iFilterLen] == strFilter:
      strAPIFunction += dictAllGroups[strGroupName]
      strURL = strBaseURL + strAPIFunction
      LogEntry("Now Pulling details about group {}".format(strGroupName))
      APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
      if "agents" in APIResponse:
        if isinstance(APIResponse["agents"],list):
          for dictAgent in APIResponse["agents"]:
            LogEntry ("{} {}".format(dictAgent["name"],dictAgent["uuid"]))
            lstAssets.append(dictAgent["uuid"])



      # if strName not in dictAllValues:
      #   LogEntry ("Creating a new value with name and members of the group")
      #   dictPayload["category_name"] = "AgentGroups"
      #   dictPayload["value"] = strName
      #   dictPayload["description"] = "Created by a sync script from Agent Group ID {}".format(strID)
      #   strMethod = "post"
      #   strAPIFunction = "tags/values/"
      #   strURL = strBaseURL + strAPIFunction
      #   LogEntry("Submitting request to create")
      #   APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
      #   if isinstance(APIResponse,dict):
      #     if "uuid" in APIResponse:
      #       LogEntry("Tag Value created successfully. ID:{}".format(APIResponse["uuid"]))
      #     else:
      #       LogEntry("No UUID\n{}".format(APIResponse),True)
      #   else:
      #     LogEntry("Response for group {} is not dictionary\n{}".format(strName, APIResponse))


    else:
      LogEntry("Skipping group {}".format(strGroupName))

      

        
        
  iRowCount += 1


  LogEntry("Done!")

if __name__ == '__main__':
  main()
