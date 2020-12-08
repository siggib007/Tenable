'''
Tenable API Script to pull details about Access Groups and write to CSV
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

def ISO8601Date2Str(strDate):
  #   Converst ISO 8601 Date of 1994-11-05T13:15:30Z to 1994-11-05 13:15:30 GMT
  if strDate == "":
    return ""
  if strDate is None:
    return ""
  strTemp = CleanStr(strDate)
  strTemp = strTemp.replace("T"," ")
  return strTemp.replace("Z"," GMT")

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

def GetGroups():
  dictPayload = {}
  strMethod = "get"
  strAPIFunction = "v2/access-groups"
  strURL = strBaseURL + strAPIFunction
  LogEntry("Pulling a base list of Groups")
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if "access_groups" in APIResponse:
    if isinstance(APIResponse["access_groups"],list):
      return APIResponse["access_groups"]
    else:
        LogEntry("access_groups is not a list, no idea what to do with this: {}".format(APIResponse),True)
  else:
    LogEntry ("Unepxected results: {}".format(APIResponse),True)

def GroupDetails(lstGroups):
  dictPayload = {}
  strMethod = "get"
  
  LogEntry ("Starting to fetch details. Creating the CSV file {} ".format(strCSVName))
  objCSVOut = open(strCSVName,"w",1)
  objCSVOut.write("Group ID,Name,Type,Create at,Created By,Updated at,Updated By,Rules,Principals\n")
  
  for dictGroup in lstGroups:
    if "id" in dictGroup:
      strID = dictGroup["id"]
    else:
      LogEntry("No ID in record, skipping")
      continue
    if "created_at" in dictGroup:
      strCreateDT = ISO8601Date2Str(dictGroup["created_at"])
    else:
      strCreateDT = "No Create Date"
    if "updated_at" in dictGroup:
      strUpdateDT = ISO8601Date2Str(dictGroup["updated_at"])
    else:
      strUpdateDT = "No update Date"
    if "name" in dictGroup:
      strName = dictGroup["name"]
    else:
      strName = "NoName"
    if "access_group_type" in dictGroup:
      strType = dictGroup["access_group_type"]
    else:
      strType = "No Type"
    if "created_by_name" in dictGroup:
      strCreateName = dictGroup["created_by_name"]
    else:
      strCreateName = "No create name"
    if "updated_by_name" in dictGroup:
      strUpdateName = dictGroup["updated_by_name"]
    else:
      strUpdateName = "No update name"
    LogEntry("Fetching Group {} | {} ".format(strName,strID))
    strAPIFunction = "v2/access-groups/" + str(strID)
    strURL = strBaseURL + strAPIFunction
    APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
    if "rules" in APIResponse:
      if isinstance(APIResponse["rules"],list):
        # strRules = "List of {} rules".format(len(APIResponse["rules"]))
        dictRules=APIResponse["rules"][0]
        if isinstance(dictRules["terms"],list):
          iTerms = len(dictRules["terms"])
          if iTerms < 5:
            strTerms = "|".join(dictRules["terms"])
          else:
            strTerms = "list of {} items".format(iTerms)
        else:
          strTerms = "Terms is not a list"
        strRules = "{} {} {} ".format(dictRules["type"],dictRules["operator"],strTerms)
      else:
        strRules = "Rules does not contain a list"
    else:
      strRules = "There are no rules"
    if "principals" in APIResponse:
      if isinstance(APIResponse["principals"],list):
        # strPrincipals = "List of {} principals".format(len(APIResponse["principals"]))
        lstPrincipals = []
        for dictPrincipals in APIResponse["principals"]:
          if dictPrincipals["type"] == "all_users":
            strPType = dictPrincipals["principal_name"]
          else:
            strPType = " {} {} ".format(dictPrincipals["type"],dictPrincipals["principal_name"])
          strTemp = " {} {} ".format(strPType,";".join(dictPrincipals["permissions"]))
          lstPrincipals.append(strTemp)
        strPrincipals = "|".join(lstPrincipals)
      else:
        strPrincipals = "principals does not contain a list"
    else:
      strPrincipals = "There are no principals"

    objCSVOut.write("{},{},{},{},{},{},{},{},{} \n".format(strID,strName,strType,strCreateDT,strCreateName,
      strUpdateDT,strUpdateName,strRules,strPrincipals))

  objCSVOut.close()

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
  global strCSVName

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

  if not os.path.exists (strLogDir) :
    os.makedirs(strLogDir)
    print ("\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))

  strScriptName = os.path.basename(sys.argv[0])
  iLoc = strScriptName.rfind(".")
  strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
  strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
  strScriptHost = platform.node().upper()

  print ("This is a script to pull details on Access Groups via API. This is running under Python Version {}".format(strVersion))
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
  
  if "OutFile" in dictConfig:
    strCSVName = dictConfig["OutFile"]
  else:
    LogEntry("no output provided, unable to continue",True)


  lstAllGroups = GetGroups()
  GroupDetails(lstAllGroups)

  LogEntry("Done!")

if __name__ == '__main__':
  main()
