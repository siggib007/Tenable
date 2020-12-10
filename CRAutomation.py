'''
Tenable API Script to check for current Nessus Agent Version and alert if it is new
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
import datetime
import urllib.parse as urlparse
import subprocess as proc
import json
import platform
# End imports

#avoid insecure warning
requests.urllib3.disable_warnings()

#Define few things
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
iDefCRDelta = 2 # Default number of days for CR Planned Start
iDefCRDur = 7 # Default number of days for a CR to be active
iTotalSleep = 0
tLastCall = 0
iLineCount = 0
iTotalScan = 0

def VersionCmp(strOld, strNew):
  LogEntry("Comparing {} and {} ".format(strOld, strNew))
  lstOldParts = strOld.split(".")
  lstNewParts = strNew.split(".")
  if len(lstOldParts) != 3 or len(lstNewParts) != 3:
    SendNotification("Invalid versions during version compare in {} ".format(strScriptName))
    return False
  elif not isInt(lstOldParts[0]) or not isInt(lstOldParts[1]) or not isInt(lstOldParts[2]) \
     or not isInt(lstNewParts[0]) or not isInt(lstNewParts[1]) or  not isInt(lstNewParts[2]):
      SendNotification("Invalid versions during version compare in {} ".format(strScriptName))
      return False

  if lstNewParts[0] > lstOldParts[0]:
    return True
  elif lstNewParts[0] == lstOldParts[0]:
    if lstNewParts[1] > lstOldParts[1]:
      return True
    elif lstNewParts[1] == lstOldParts[1]:
      if lstNewParts[2] > lstOldParts[2]:
        return True
      else:
        return False
    else:
      return False
  else:
    return False
       
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
  LogEntry ("Trying to send notification for: {} ".format(strMsg))
  if not bNotifyEnabled:
    LogEntry ("notify not enabled")
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

def MakeAPICall (strURL, strHeader, strMethod, dictPayload="", strUserName="", strPWD=""):

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

  if strUserName == "" or strPWD == "":
    bAuth = False
  else:
    bAuth = True

  # LogEntry ("Doing a {} to URL: \n {}\n with payload of {}".format(strMethod,strURL,dictPayload))
  try:
    if not bAuth:
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
    else:
      if strMethod.lower() == "get":
        WebRequest = requests.get(strURL, headers=strHeader, verify=False, auth=(strUserName, strPWD))
        # LogEntry ("get executed")
      if strMethod.lower() == "post":
        if dictPayload != "":
          WebRequest = requests.post(strURL, json= dictPayload, headers=strHeader, verify=False, auth=(strUserName, strPWD))
        else:
          WebRequest = requests.post(strURL, headers=strHeader, verify=False, auth=(strUserName, strPWD))
        # LogEntry ("post executed")
      if strMethod.lower() == "put":
        if dictPayload != "":
          WebRequest = requests.put(strURL, json= dictPayload, headers=strHeader, verify=False, auth=(strUserName, strPWD))
        else:
          WebRequest = requests.put(strURL, headers=strHeader, verify=False, auth=(strUserName, strPWD))
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
    # LogEntry (WebRequest.text)
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

def FetchNewVer ():
  dictPayload = {}
  dictResult = {}
  strMethod = "get"
  strAPIFunction = "downloads/api/v2/pages/nessus-agents"
  strURL = strBaseURL + strAPIFunction
  LogEntry("Pulling a list of existing Nessus Agent releases")
  APIResponse = MakeAPICall(strURL,strTNBLHeader,strMethod, dictPayload)
  if "releases" in APIResponse:
    if "latest" in APIResponse["releases"]:
      for strKey in APIResponse["releases"]["latest"].keys():
        if strKey[:13] == "Nessus Agents":
          if isinstance(APIResponse["releases"]["latest"][strKey],list):
            dictResult["NewVer"] = APIResponse["releases"]["latest"][strKey][0]["version"]
            dictResult["ReleaseDT"] = APIResponse["releases"]["latest"][strKey][0]["product_release_date"]
            LogEntry ("Latest Version is {} with release date of {} ".format(dictResult["NewVer"],dictResult["ReleaseDT"]))
          else:
            LogEntry ("Latest release of {} is not list, this can't be.".format(strKey),True)
    else:
      LogEntry ("No latest branch in the release list, can't deal",True)
  else:
    LogEntry ("Unepxected results: {}".format(APIResponse),True)
  return dictResult

def CreateCR (strNewVersion,strReleaseDT,iDeltaStart,iDuration):
  dtUTCNow = datetime.datetime.utcnow().replace(microsecond=0)
  dtStart = dtUTCNow+datetime.timedelta(days=iDeltaStart)
  dtStop = dtStart+datetime.timedelta(days=iDuration)
  strStartDT = dtStart.isoformat()+"Z"
  strStopDT = dtStop.isoformat()+"Z"
  strMethod = "post"
  strAPIFunction = "itsm/change/v2/create/"
  dictCRHeader = {}
  dictPayload = {}
  dictCRHeader["user-id"] = strTicketOwner
  dictCRHeader["Accept"] = "application/json"
  dictCRHeader["Content-Type"] = "application/json"
  dictCRHeader["Authorization"] = "Bearer " + strAccessToken
  dictPayload["impact"] = "No Impact"
  dictPayload["plannedStart"] = strStartDT
  dictPayload["plannedEnd"] = strStopDT
  dictPayload["crShortDescription"] = "Tenable Nessus Agent Update"
  dictPayload["crDescription"] = ("Tenable nessus Agent Update Automation. "
        "Upgrading to Version is {} with release date of {}").format(strNewVersion,strReleaseDT)
  strURL = strITSMURL + strAPIFunction+strActivity
  LogEntry("Submitting Ticket creation")
  APIResponse = MakeAPICall(strURL,dictCRHeader,strMethod, dictPayload)
  if isinstance(APIResponse,str):
    SendNotification ("Unexpected API Response: {} ".format(APIResponse))
  elif isinstance(APIResponse,dict):
    if "data" in APIResponse:
      if "cRID" in APIResponse["data"][0]:
        strCRNum = APIResponse["data"][0]["cRID"]
      else:
        strCRNum = "No CR Num"
        SendNotification("CR possible created but no CR number returned")
    else:
      SendNotification ("No data element returned when creating a CR, something is broken")      
  else:
    SendNotification ("API response was type {} which is totally unexpected")
  return strCRNum

def UpdateCR (strCRNum,strAction,dictBody):
  strMethod = "put"
  strAPIFunction = "itsm/change/v2/"
  dictCRHeader = {}
  dictCRHeader["user-id"] = strTicketOwner
  dictCRHeader["Accept"] = "application/json"
  dictCRHeader["Content-Type"] = "application/json"
  dictCRHeader["Authorization"] = "Bearer " + strAccessToken
  strURL = strITSMURL + strAPIFunction+strCRNum+strAction
  LogEntry("Searching for Deployment ready tickets")
  APIResponse = MakeAPICall(strURL,dictCRHeader,strMethod, dictBody)
  if isinstance(APIResponse,str):
    SendNotification ("Unexpected API Response: {} ".format(APIResponse))
  elif isinstance(APIResponse,dict):
    if "data" in APIResponse:
      if "status" in APIResponse["data"][0]:
        strStatus = APIResponse["data"][0]["status"]
        LogEntry("CR {} updated, status {}".format(strCRNum,strStatus))
      else:
        strStatus = "No Status available"
        SendNotification("CR possible update but no status returned")
    else:
      SendNotification ("No data element returned when creating a CR, something is broken")      
  else:
    SendNotification ("API response was type {} which is totally unexpected")

def main():
  global ISO
  global bNotifyEnabled
  global iMinQuiet
  global iTimeOut
  global iTotalSleep
  global objLogOut
  global strBaseDir
  global strNotifyChannel
  global strNotifyToken
  global strNotifyURL
  global strScriptHost
  global strScriptName
  global tLastCall
  global tStart
  global strTNBLHeader
  global strBaseURL
  global strTicketOwner
  global strAccessToken
  global strITSMURL
  global strActivity

  strNotifyToken = None
  strNotifyChannel = None
  strNotifyURL = None
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  tStart=time.time()
  dictPayload = {}
  dictResult = {}

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

  if os.path.isfile(strCacheFile):
    objCache = open(strCacheFile,"r")
    strLastVer = objCache.readline()
    objCache.close()
  else:
    strLastVer = "unknown"

  if not os.path.exists (strLogDir) :
    os.makedirs(strLogDir)
    print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))

  strScriptName = os.path.basename(sys.argv[0])
  iLoc = strScriptName.rfind(".")
  strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
  strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
  strScriptHost = platform.node().upper()

  print ("This is a script to find current Nessus Agent version via API and determine if it is newer than current. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)
  
  dictConfig = processConf(strConf_File)

  if "Auth" in dictConfig :
    strTNBLHeader={
      'Content-type':'application/json',
      'Authorization':'Bearer ' + dictConfig["Auth"] 
      }
  else:
    LogEntry("API Keys not provided, exiting.",True)

  if "APIBaseURL" in dictConfig:
    strBaseURL = dictConfig["APIBaseURL"]
  else:
    CleanExit("No Base API provided")
  if strBaseURL[-1:] != "/":
    strBaseURL += "/"

  bNotifyEnabled = False
  
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

  if "DeltaStart" in dictConfig:
    if isInt(dictConfig["DeltaStart"]):
      iCRDeltaStart = int(dictConfig["DeltaStart"])
    else:
      LogEntry("Invalid DeltaStart, setting to defaults of {}".format(iDefCRDelta))

  if "CRDuration" in dictConfig:
    if isInt(dictConfig["CRDuration"]):
      iCRDuration = int(dictConfig["CRDuration"])
    else:
      LogEntry("Invalid CRDuration, setting to defaults of {}".format(iDefCRDur))

  if "ITSMURL" in dictConfig:
    strITSMURL = dictConfig["ITSMURL"]
  else:
    CleanExit("No ITSMURL provided")
  if strITSMURL[-1:] != "/":
    strITSMURL += "/"
  if "ClientID" in dictConfig:
    strClientID = dictConfig["ClientID"]
  else:
    CleanExit("No ClientID provided")

  if "Secret" in dictConfig:
    strSecret = dictConfig["Secret"]
  else:
    CleanExit("No Secret provided")

  if "Activity" in dictConfig:
    strActivity = dictConfig["Activity"]
  else:
    CleanExit("No Activity provided")

  if "TicketOwner" in dictConfig:
    strTicketOwner = dictConfig["TicketOwner"]
  else:
    CleanExit("No TicketOwner provided")

  if "ConsumerName" in dictConfig:
    strConsumerName = dictConfig["ConsumerName"]
  else:
    CleanExit("No Consumer Name provided")

  # Fetching Oauth Token for Pier2.0
  strMethod = "post"
  strAPIFunction = "oauth2/v6/tokens"
  strCRHeader = ""
  strURL = strITSMURL + strAPIFunction
  LogEntry("Fetching OAuth Token")
  APIResponse = MakeAPICall(strURL,strCRHeader,strMethod, dictPayload,strClientID,strSecret)
  if "access_token" in APIResponse:
    strAccessToken = APIResponse["access_token"]
  else:
    LogEntry ("failed to fetch token, here is what I got back {} ".format(APIResponse),True)

  # Pulling list of deployment ready tickets
  strMethod = "post"
  strAPIFunction = "itsm/change/v2/search"
  dictCRHeader = {}
  dictCRHeader["user-id"] = strTicketOwner
  dictCRHeader["Accept"] = "application/json"
  dictCRHeader["Content-Type"] = "application/json"
  dictCRHeader["consumer-name"] = strConsumerName
  dictCRHeader["Authorization"] = "Bearer " + strAccessToken
  dictPayload["query"] = "(createdBy = '{}' AND status = 'Deployment Ready')".format(strTicketOwner)
  strURL = strITSMURL + strAPIFunction
  LogEntry("Searching for Deployment ready tickets")
  APIResponse = MakeAPICall(strURL,dictCRHeader,strMethod, dictPayload)
  if isinstance(APIResponse,str):
    LogEntry ("Unexpected API Response: {} ".format(APIResponse))
  elif isinstance(APIResponse,dict):
    LogEntry ("got a dict back which is good. Here are the keys {} ".format(APIResponse.keys()))
  else:
    LogEntry ("API response was type {} which is totally unexpected")


  # Check for new version
  LogEntry ("Last known version was {} ".format(strLastVer))
  dictResult = FetchNewVer()
  strNewVer = dictResult["NewVer"]
  bNew = VersionCmp(strLastVer,strNewVer)
  if bNew:
    LogEntry ("You have a new version. Creating a {} CR".format(strActivity))
    # Create a CR 
    strCRNumber = CreateCR(strNewVer,dictResult["ReleaseDT"],iCRDeltaStart,iCRDuration)
    UpdateCR(strCRNumber,"/request-change","")
    objCache = open(strCacheFile,"w",1)
    objCache.write(str(strNewVer))
    objCache.close()  
  else:
    LogEntry ("Current version is either the same or older")

  LogEntry("Done!")

if __name__ == '__main__':
  main()
