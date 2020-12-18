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
strDefDateFormat="%Y-%m-%d %H:%M:%S" #Format to use if nothing else is provided

def formatUnixDate(iDate):
  if iDate > 9999999999:
    iDate = iDate / 1000
  try:
    structTime = time.localtime(iDate)
    strDate = time.strftime(strFormat,structTime)
  except Exception as err:
    LogEntry ("Error converting {} to formated date. {}".format(iDate,err))
    strDate = "Invalid Date"
  return strDate

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
  strMsg = strScriptName + ": " + strMsg
  dictNotify = {}
  dictNotify["token"] = dictConfig["NotifyToken"]
  dictNotify["channel"] = dictConfig["NotifyChannel"]
  dictNotify["text"]=strMsg[:199]
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

  dictReturn = {}

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
    dictReturn["code"] = "NoneType"
    dictReturn["Text"] = "response is none type"
    return dictReturn

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type")
    dictReturn["code"] = "ResponseErr"
    dictReturn["Text"] = "response is unknown type"
    return dictReturn

  # LogEntry ("call resulted in status code {}".format(WebRequest.status_code))

  dictReturn["code"] = WebRequest.status_code
  dictReturn["Text"] = WebRequest.text
  try:
    dictReturn["json"] = WebRequest.json()
  except Exception as err:
    LogEntry ("Issue with converting response to json. Error:{}".format(err))
  return dictReturn

def CleanStr(strOld):
  strTemp = strOld.replace('"','')
  strTemp = strTemp.replace(',','')
  strTemp = strTemp.replace('\n','')
  return strTemp.strip()

def StartStop(strCrit):
  LogEntry("Searching for: {}".format(strCrit))
  dictPayload = {}
  strMethod = "post"
  strAPIFunction = "itsm/change/v2/search"
  dictCRHeader = {}
  dictCRHeader["user-id"] = strTicketOwner
  dictCRHeader["Accept"] = "application/json"
  dictCRHeader["Content-Type"] = "application/json"
  dictCRHeader["consumer-name"] = strConsumerName
  dictCRHeader["Authorization"] = "Bearer " + strAccessToken
  dictPayload["query"] = strCrit
  strURL = strITSMURL + strAPIFunction
  dictReturn = MakeAPICall(strURL,dictCRHeader,strMethod, dictPayload)
  if dictReturn["code"] != 200:
    LogEntry ("HTTP Error {}: {}".format(dictReturn["code"],dictReturn["Text"]))
  else:
    dictJSONResult = dictReturn["json"]
    if "data" in dictJSONResult:
      if isinstance(dictJSONResult["data"],list):
        for dictData in dictJSONResult["data"]:
          if "crid" in dictData:
            strCRID = "CR" + str(dictData["crid"])
          else:
            strCRID = "No CR ID"
            LogEntry("Missing CR ID")
          if "plannedStart" in dictData:
            iPlannedStart = dictData["plannedStart"]
          else:
            iPlannedStart = "999999999999999"
            LogEntry("No Planned Start date on {}".format(strCRID))
          if "plannedEnd" in dictData:
            iPlannedEnd = dictData["plannedEnd"]
          else:
            iPlannedEnd = "999999999999999"
            LogEntry("No Planned End date on {}".format(strCRID))
          if "status" in dictData:
            strStatus = dictData["status"]
          else:
            strStatus = "No Status"
            LogEntry("No status on {}".format(strCRID))

          if strStatus == "Deployment Ready":
            # LogEntry ("The following CRs are ready for deployment as of now {}".format(time.time()))
            if iPlannedStart/1000 > time.time():
              LogEntry ("{} is deployment ready with planned start of {}. Waiting to start until then".format(strCRID,
                formatUnixDate(iPlannedStart)))
            else:
              LogEntry("{} is deployment ready with planned start in the past, starting CR".format(strCRID))
              dictPayload = {}
              strStatus = UpdateCR(strCRID,"/start",dictPayload)
              if strStatus != "unknown":
                SendNotification("{} updated, current status: {}".format(strCRID,strStatus))
          elif strStatus == "Implementation - In Progress":
            # LogEntry ("The following CRs are ready to be stopped as of now {}".format(time.time()))
            iActualEnd = (iPlannedEnd/1000) - (iCRDeltaStop * 86400)
            if iActualEnd > time.time():
              LogEntry ("{} is in progress and planned end is {}. Waiting to end until closer to that".format(strCRID,
                formatUnixDate(iPlannedEnd)))
            else:
              LogEntry("{} is in progress and planned end is {}, which is in past or in the next {} of days, stopping the CR".format(
                strCRID,formatUnixDate(iPlannedEnd),iCRDeltaStop))
              dictPayload = {}
              strStatus = UpdateCR(strCRID,"/stop",dictPayload)
              if strStatus != "unknown":
                SendNotification("{} updated, current status: {}".format(strCRID,strStatus))
              dictPayload = {"subStatus": "Complete/In Production – No Issues","closeComment": "Complete"}
              strStatus = UpdateCR(strCRID,"/save",dictPayload)
              dictPayload = {}
              strStatus = UpdateCR(strCRID,"/close",dictPayload)              
              if strStatus != "unknown":
                SendNotification("{} updated, current status: {}".format(strCRID,strStatus))
          elif strStatus == "Implemented":
            LogEntry("{} is implemented, Closing the CR".format(strCRID))
            dictPayload = {"subStatus": "Complete/In Production – No Issues","closeComment": "Complete"}
            strStatus = UpdateCR(strCRID,"/save",dictPayload)
            dictPayload = {}
            strStatus = UpdateCR(strCRID,"/close",dictPayload)
            if strStatus != "unknown":
              SendNotification("{} updated, current status: {}".format(strCRID,strStatus))
          elif strStatus == "Draft":
            LogEntry("{} is draft, submitting for change".format(strCRID))
            dictPayload = {}
            strStatus = UpdateCR(strCRID,"/request-change",dictPayload)
            if strStatus != "unknown":
              SendNotification("{} updated, current status: {}".format(strCRID,strStatus))
          else:
            LogEntry("{} has a status of {} start:{} end:{} no case for that".format(strCRID,strStatus,
              formatUnixDate(iPlannedStart),formatUnixDate(iPlannedEnd)))
      else:
        LogEntry("Data element in response not a list, why ???",True)
    else:
      LogEntry("No Data element in reponse, WTF???",True)

def FetchNewVer ():
  dictPayload = {}
  dictResult = {}
  strMethod = "get"
  strAPIFunction = "downloads/api/v2/pages/nessus-agents"
  strURL = strBaseURL + strAPIFunction
  LogEntry("Pulling a list of existing Nessus Agent releases")
  dictReturn = MakeAPICall(strURL,strTNBLHeader,strMethod, dictPayload)
  if dictReturn["code"] != 200:
    LogEntry ("HTTP Error {}: {}".format(dictReturn["code"],dictReturn["Text"]))
  else:
    dictJSONResult = dictReturn["json"]
  if "releases" in dictJSONResult:
    if "latest" in dictJSONResult["releases"]:
      for strKey in dictJSONResult["releases"]["latest"].keys():
        if strKey[:13] == "Nessus Agents":
          if isinstance(dictJSONResult["releases"]["latest"][strKey],list):
            dictResult["NewVer"] = dictJSONResult["releases"]["latest"][strKey][0]["version"]
            dictResult["ReleaseDT"] = dictJSONResult["releases"]["latest"][strKey][0]["product_release_date"]
            LogEntry ("Latest Version is {} with release date of {} ".format(dictResult["NewVer"],dictResult["ReleaseDT"]))
            break
          else:
            LogEntry ("Latest release of {} is not list, this can't be.".format(strKey),True)
    else:
      LogEntry ("No latest branch in the release list, can't deal",True)
  else:
    LogEntry ("Unepxected results: {}".format(dictJSONResult),True)
  return dictResult

def CreateCR (strNewVersion,strReleaseDT,iDeltaStart,iDuration):
  dtUTCNow = datetime.datetime.utcnow().replace(microsecond=0)
  dtStart = dtUTCNow+datetime.timedelta(days=iDeltaStart)
  dtStop = dtStart+datetime.timedelta(days=iDuration)
  strStartDT = dtStart.isoformat()+"Z"
  strStopDT = dtStop.isoformat()+"Z"
  strCRNum = ""
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
  dictReturn = MakeAPICall(strURL,dictCRHeader,strMethod, dictPayload)
  if dictReturn["code"] != 200:
    LogEntry ("HTTP Error {}: {}".format(dictReturn["code"],dictReturn["Text"]))
  else:
    dictJSONResult = dictReturn["json"]
    if "data" in dictJSONResult:
      if "cRID" in dictJSONResult["data"][0]:
        strCRNum = dictJSONResult["data"][0]["cRID"]
        LogEntry("Created {}".format(strCRNum))
      else:
        SendNotification("CR possible created but no CR number returned")
    else:
      SendNotification ("No data element returned when creating a CR, something is broken")      
  return strCRNum

def ErrorParse(dictReturn):
  strErrMsg = ""
  # strCode = dictReturn["code"]
  if "Text" in dictReturn:
    strText = dictReturn["Text"]
  else:
    strText = "No details available"
  if "json" in dictReturn:
    if "data" in dictReturn["json"]:
      if "errors" in dictReturn["json"]["data"]:
        if isinstance(dictReturn["json"]["data"]["errors"],list):
          for dictError in dictReturn["json"]["data"]["errors"]:
            if "field" in dictError:
              strFields = dictError["field"]
            else:
              strFields = "unknown"
            if "message" in dictError:
              strMessage = dictError["message"]
            else:
              strMessage = "error no message"
            strErrMsg += "{} : {}\n".format(strFields,strMessage)
        else:
          LogEntry("Data Errors is not a list, don't know how to parse that. Here is what I got: {}".format(strText))
          strErrMsg = "Unknown Error details, please check logs"
      else:
        LogEntry("No errors collection, no idea where the error is. Here is what I got: {}".format(strText))
        strErrMsg = "Unknown Error details, please check logs"
    else:
      LogEntry("No data collection, no idea where the error is. Here is what I got: {}".format(strText))
      strErrMsg = "Unknown Error details, please check logs"
  else:
    LogEntry("No json collection, no idea where the error is. Here is what I got: {}".format(strText))
    strErrMsg = "Unknown Error details, please check logs"
  return strErrMsg
    

def UpdateCR (strCRNum,strAction,dictBody):
  LogEntry("Going to update {} with {} and body of {}".format(strCRNum,strAction,dictBody))
  strMethod = "put"
  strAPIFunction = "itsm/change/v2/"
  dictCRHeader = {}
  strStatus = "unknown"
  dictCRHeader["user-id"] = strTicketOwner
  dictCRHeader["Accept"] = "application/json"
  dictCRHeader["Content-Type"] = "application/json"
  dictCRHeader["Authorization"] = "Bearer " + strAccessToken
  strURL = strITSMURL + strAPIFunction+strCRNum+strAction
  dictReturn = MakeAPICall(strURL,dictCRHeader,strMethod, dictBody)
  if dictReturn["code"] != 200:
    strErrMsg = ErrorParse(dictReturn)
    SendNotification("Update to {} Failed: {}".format(strCRNum,strErrMsg))
  else:
    dictJSONResult = dictReturn["json"]
    if "data" in dictJSONResult:
      if "status" in dictJSONResult["data"][0]:
        strStatus = dictJSONResult["data"][0]["status"]
        LogEntry("CR {} updated, status {}".format(strCRNum,strStatus))
      else:
        strStatus = "No Status available"
        SendNotification("CR possible updated but no status returned")
    else:
      SendNotification ("No data element returned when creating a CR, something is broken")      
  return strStatus

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
  global strConsumerName
  global dictConfig
  global strFormat
  global iCRDeltaStop

  strNotifyToken = None
  strNotifyChannel = None
  strNotifyURL = None
  bNotifyEnabled = False
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

  if "NotifyEnabled" in dictConfig:
    if dictConfig["NotifyEnabled"].lower() == "yes" \
      or dictConfig["NotifyEnabled"].lower() == "true":
      bNotifyEnabled = True
    else:
      bNotifyEnabled = False

  if "NotifyToken" in dictConfig and "NotifyChannel" in dictConfig and "NotificationURL" in dictConfig:
    bNotifyEnabled = True
  else:
    bNotifyEnabled = False
    LogEntry("Missing configuration items for Slack notifications, "
      "turning slack notifications off")

  
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
      iCRDeltaStart = iDefCRDelta
  else:
    LogEntry("Missing Deltastart, using defaults of {}".format(iDefCRDelta))
    iCRDeltaStart = iDefCRDelta

  if "DeltaStop" in dictConfig:
    if isInt(dictConfig["DeltaStop"]):
      iCRDeltaStop = int(dictConfig["DeltaStop"])
    else:
      LogEntry("Invalid DeltaStop, setting to defaults of {}".format(iDefCRDelta))
      iCRDeltaStop = iDefCRDelta
  else:
    LogEntry("Missing Deltastop, using defaults of {}".format(iDefCRDelta))
    iCRDeltaStop = iDefCRDelta

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

  if "DateTimeFormat" in dictConfig:
    strFormat = dictConfig["DateTimeFormat"]
  else:
    strFormat = strDefDateFormat

  # Fetching Oauth Token for Pier2.0
  strMethod = "post"
  strAPIFunction = "oauth2/v6/tokens"
  strCRHeader = ""
  strURL = strITSMURL + strAPIFunction
  LogEntry("Fetching OAuth Token")
  dictReturn = MakeAPICall(strURL,strCRHeader,strMethod, dictPayload,strClientID,strSecret)
  if dictReturn["code"] != 200:
    LogEntry ("HTTP Error {}: {}".format(dictReturn["code"],dictReturn["Text"]))
  else:
    dictJSONResult = dictReturn["json"]

  if "access_token" in dictJSONResult:
    strAccessToken = dictJSONResult["access_token"]
  else:
    LogEntry ("failed to fetch token, here is what I got back {} ".format(dictJSONResult),True)

  # Pulling list of tickets to start or stop
  StartStop("(createdBy = '{}' AND status != 'Closed') ".format(strTicketOwner))

  # Check for new version
  dictPayload = {}
  LogEntry ("Last known version was {} ".format(strLastVer))
  dictResult = FetchNewVer()
  strNewVer = dictResult["NewVer"]
  bNew = VersionCmp(strLastVer,strNewVer)
  if bNew:
    LogEntry ("You have a new version. Creating a {} CR".format(strActivity))
    # Create a CR 
    strCRNumber = CreateCR(strNewVer,dictResult["ReleaseDT"],iCRDeltaStart,iCRDuration)
    if strCRNumber != "":
      strStatus = UpdateCR(strCRNumber,"/request-change",dictPayload)
      SendNotification("{} created to update Nessus Agent to version {} released {}. CR Status {}".format(
        strCRNumber,strNewVer,dictResult["ReleaseDT"],strStatus))
      objCache = open(strCacheFile,"w",1)
      objCache.write(str(strNewVer))
      objCache.close()
    else:
      SendNotification("Did not update CR or script cache due to lack of CR number")
  else:
    LogEntry ("Current version is either the same or older")

  LogEntry("Done!")

if __name__ == '__main__':
  main()
