'''
Tenable API Script to sync Target Groups to Tags
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
  dictReturn["dns"] = ",".join(lstHost)
  return dictReturn

def main():
  global ISO
  global bNotifyEnabled
  # global dictConfig
  # global iLoc
  global iMinQuiet
  global iTimeOut
  global iTotalSleep
  global objLogOut
  global strBaseDir
  # global strBaseURL
  global strFormat
  global strNotifyChannel
  global strNotifyToken
  global strNotifyURL
  global strScriptHost
  global strScriptName
  global tLastCall
  global tStart
  # global strHeader

  strNotifyToken = None
  strNotifyChannel = None
  strNotifyURL = None
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  iRowCount = 1
  tStart=time.time()

  dictCount = {}  

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

  if not os.path.exists (strLogDir) :
    os.makedirs(strLogDir)
    print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))

  strScriptName = os.path.basename(sys.argv[0])
  iLoc = strScriptName.rfind(".")
  strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
  strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
  strScriptHost = platform.node().upper()

  print ("This is a script to sync Target Group to Tags via API. This is running under Python Version {}".format(strVersion))
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
            # LogEntry ("{}: {}".format(strValue,strValueID))
    else:
        LogEntry("Values is not a list, no idea what to do with this: {}".format(APIResponse),True)
  else:
    LogEntry ("Unepxected results: {}".format(APIResponse),True)

  strMethod = "get"
  strAPIFunction = "target-groups/"
  strURL = strBaseURL + strAPIFunction
  LogEntry("Now Pulling all Target Groups and transfering them to Tag Values")
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)

  if "target_groups" in APIResponse:
    if isinstance(APIResponse["target_groups"],list):
        iTGSize = len(APIResponse["target_groups"])
        for dictTG in APIResponse["target_groups"]:
          strType = dictTG["type"]
          strMembers = dictTG["members"]
          strName = dictTG["name"]
          if strName == "Default":
            #Don't try to convert the default group
            continue
          lstMembers = strMembers.split(",")
          iMemberCount = len(lstMembers)
          if iMemberCount < 10000:
            dictMembers = CheckMembers(lstMembers)
          else:
            #skip this group, it has too many members
            continue
          strID = dictTG["id"]
          dictCount[strName] = iMemberCount
          LogEntry ("Processing group {} with ID {}. Contains {} entries. Group {} out of {}".format(strName,strID,iMemberCount,iRowCount,iTGSize))
          dictPayload = {}
          dictFilterObj = {}
          if dictMembers["ipv4"] != "":
            dictFilterObj["field"] = "ipv4"
            dictFilterObj["operator"] = "eq"
            dictFilterObj["value"] = dictMembers["ipv4"]
          dictFilters = {}
          dictFilters["asset"] = {}
          dictFilters["asset"]["and"] = []
          dictFilters["asset"]["and"].append(dictFilterObj)
          dictPayload["filters"] = dictFilters
          if strName in dictAllValues:
            LogEntry ("Tag Value already exists, updating tag value with ID {}".format(dictAllValues[strName]))
            strAPIFunction = "tags/values/{}".format(dictAllValues[strName])
            strMethod = "put"
            strAction = "update"
          else:
            LogEntry ("Creating a new value with name and members of the group")
            dictPayload["category_name"] = strType + "TG"
            dictPayload["value"] = strName
            dictPayload["description"] = "Created by a sync script from Target Group ID {}".format(strID)
            strMethod = "post"
            strAPIFunction = "tags/values/"
            strAction = "create"
            # LogEntry("Payload: {}".format(dictPayload))

          strURL = strBaseURL + strAPIFunction
          LogEntry("Submitting request to {}".format(strAction))
          APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
          if isinstance(APIResponse,dict):
            if "uuid" in APIResponse:
              LogEntry("Tag Value {}d successfully. ID:{}".format(strAction, APIResponse["uuid"]))
            else:
              LogEntry("No UUID\n{}".format(APIResponse),True)
          else:
            LogEntry("Response for group {} with {} entries is not dictionary\n{}".format(strName, iMemberCount, APIResponse))
          iRowCount += 1

  # for strGroup in dictCount:
  #   LogEntry ("{},{}".format(strGroup,dictCount[strGroup]))
  LogEntry("Done!")

if __name__ == '__main__':
  main()
