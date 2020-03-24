'''
Tenable agent List API Script
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
import time
import urllib.parse as urlparse
import json
import platform
# End imports

#avoid insecure warning
requests.packages.urllib3.disable_warnings()

def getInput(strPrompt):
    if sys.version_info[0] > 2 :
        return input(strPrompt)
    else:
      print("Please upgrade to Python 3")
      sys.exit()
# end getInput


def SendNotification (strMsg):
  if not bNotifyEnabled:
    return "notifications not enabled"
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
  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,
    strScriptHost, strCause))
  objLogOut.close()
  print ("objLogOut closed")
  if objFileOut is not None:
    objFileOut.close()
    print ("objFileOut closed")
  else:
    print ("objFileOut is not defined yet")
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    SendNotification("{} on {}: {}".format (strScriptName,strScriptHost,strMsg[:99]))
    CleanExit("")

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
        # print (":1={}\n1:3={}".format(strValue[:1],strValue[1:3]))
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

def FormatTenableDate (strdate):
  if strdate is None:
    return "None"
  if len(strdate) > 14:
    return strdate[:4]+"-"+strdate[4:6]+"-"+strdate[6:8]+" "
    +strdate[9:11]+":"+strdate[11:13]+":"+strdate[13:]
  elif len(strdate) > 12:
    return strdate[:4]+"-"+strdate[4:6]+"-"+strdate[6:8]+" "+strdate[9:11]+":"+strdate[11:]
  elif len(strdate) > 10:
    return strdate[:4]+"-"+strdate[4:6]+"-"+strdate[6:8]+" "+strdate[9:10]
  elif len(strdate) > 7:
    return strdate[:4]+"-"+strdate[4:6]+"-"+strdate[6:]
  else:
    return "Only {} characters, not a valid date".format(len(strdate))

def formatUnixDate(iDate):
  structTime = time.localtime(iDate)
  return time.strftime(strFormat,structTime)

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
    LogEntry ("It has been less than {} seconds since last API call, "
      "waiting {} seconds".format(iMinQuiet,iAddWait))
    iTotalSleep += iAddWait
    time.sleep(iAddWait)
  iErrCode = ""
  iErrText = ""
  dictResponse = {}

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
    return "There was a problem with your request. "
    "HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    try:
      return WebRequest.json()
    except Exception as err:
      LogEntry ("Issue with converting response to json. "
        "Here are the first 99 character of the response: {}".format(WebRequest.text[:99]))


def main():
  global strFileout
  global objFileOut
  global objLogOut
  global strScriptName
  global strScriptHost
  global tLastCall
  global iTotalSleep
  global strBaseDir
  global strBaseURL
  global dictConfig
  global strFormat
  global bNotifyEnabled
  global iLimit
  global iMinQuiet
  global iTimeOut

  #Define few things
  iTimeOut = 120
  iMinQuiet = 2 # Minimum time in seconds between API calls
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  dictParams = {}
  # dictParams["mode"] = "full"
  # dictParams["mode"] = "extended"  strBaseURL=None
  strFormat="%Y-%m-%dT%H:%M:%S"
  strFileout=None
  bNotifyEnabled = False
  iLimit = 5000

  strBaseDir = os.path.dirname(sys.argv[0])
  strRealPath = os.path.realpath(sys.argv[0])
  strRealPath = strRealPath.replace("\\","/")
  if strBaseDir == "":
    iLoc = strRealPath.rfind("/")
    strBaseDir = strRealPath[:iLoc]
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
  strLogDir  = strBaseDir + "Logs/"
  strOutDir  = strBaseDir + "out/"
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
  dictPayload = {}
  strScriptHost = platform.node().upper()

  print ("This is a script to download Tenable Agent list via API. "
    "This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)
  objFileOut = None

  tLastCall = 0
  iTotalSleep = 0
  tStart=time.time()
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

  if "DateTimeFormat" in dictConfig:
    strFormat = dictConfig["DateTimeFormat"]
  if "OutFile" in dictConfig:
    strFileout = dictConfig["OutFile"]

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

  dictResults={}
  if strFileout is None or strFileout =="":
    LogEntry("outfile not define, using defaults")
    strFileout = strOutDir + strScriptName[:iLoc] + "-" + strFunction + ISO + ".csv"
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

  objFileOut.write("ID,UUID,Name,Platform,Distro,IP,PluginID,Core Build,"
    "Core Version,Linked On,Last Connected,Status,Groups\n")

  lstSysArg = sys.argv
  iSysArgLen = len(lstSysArg)
  iTimeOut = 120
  iGroupID = -56
  if iSysArgLen > 1:
    strGroupName = lstSysArg[1]
    LogEntry("Getting group ID")
    strMethod = "get"
    strAPIFunction = "scanners/scanner_id/agent-groups"
    strURL = strBaseURL + strAPIFunction
    APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
    if "groups" in APIResponse:
      if isinstance(APIResponse["groups"],list):
        for dictGroups in APIResponse["groups"]:
          if dictGroups["name"]==strGroupName:
            iGroupID = dictGroups["id"]
            LogEntry("Found group {} with ID of {}".format(strGroupName, iGroupID))
      else:
        LogEntry("Groups list isn't a list???? Groups list is a {}".format(type(APIResponse["groups"])))
    else:
      LogEntry("No Groups in results, here are the first 99 character of the response: {}".format(APIResponse[99:]))
    if iGroupID == -56:
      LogEntry ("Could not find group name {}".format(strGroupName))
      strResponse = getInput ("would you like to return all agents? (y/n): ")
      strResponse = strResponse.lower()
      if strResponse == "":
        strResponse = "y"
        print ("Blank input assuming yes")
      if strResponse[0] != "y":
        print ("No problem at all, exiting")
        sys.exit(1)
  else:
    LogEntry("No parameters prvided, dumping all agents to CSV")

  if iGroupID == -56:
    strAPIFunction = "scanners/scanner_id/agents"
  else:
    strAPIFunction = "scanners/scanner_id/agent-groups/{}/agents".format(iGroupID)

  strMethod = "get"
  iTotalProcessed = 0
  iOffset = 0
  iTotalAgents = iLimit
  while iTotalProcessed < iTotalAgents:
    dictParams["limit"] = iLimit
    dictParams["offset"] = iOffset
    if isinstance(dictParams,dict) and len(dictParams) > 0:
      strListScans = urlparse.urlencode(dictParams)
      strURL = strBaseURL + strAPIFunction +"?" + strListScans
    else:
      strURL = strBaseURL + strAPIFunction
    APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
    print ("Response is {} and has len of {}".format(type(APIResponse),len(APIResponse)))
    if "agents" in APIResponse:
      print ("Agent element is {} and has len of {}".format(
        type(APIResponse["agents"]),len(APIResponse["agents"])))
      if isinstance(APIResponse["agents"],list):
        for dictAgents in APIResponse["agents"]:
          if "id" in dictAgents:
            strID = dictAgents["id"]
          else:
            strID = ""
          if "uuid" in dictAgents:
            strUUID = dictAgents["uuid"]
          else:
            strUUID = ""
          if "name" in dictAgents:
            strName = dictAgents["name"]
          else:
            strName = ""
          if "platform" in dictAgents:
            strPlatform = dictAgents["platform"]
          else:
            strPlatform = ""
          if "distro" in dictAgents:
            strDistro = dictAgents["distro"]
          else:
            strDistro = ""
          if "ip" in dictAgents:
            strIP = dictAgents["ip"]
          else:
            strIP = ""
          if "plugin_feed_id" in dictAgents:
            strPluginID = dictAgents["plugin_feed_id"]
          else:
            strPluginID = ""
          if "core_build" in dictAgents:
            strCoreBuild = dictAgents["core_build"]
          else:
            strCoreBuild = ""
          if "core_version" in dictAgents:
            strCoreVer = dictAgents["core_version"]
          else:
            strCoreVer = ""
          if "linked_on" in dictAgents:
            dtLinked = formatUnixDate(dictAgents["linked_on"])
          else:
            dtLinked = ""
          if "last_connect" in dictAgents:
            dtConnect = formatUnixDate (dictAgents["last_connect"])
          else:
            dtConnect = ""
          if "status" in dictAgents:
            strStatus = dictAgents["status"]
          else:
            strStatus = ""
          if "groups" in dictAgents:
            if isinstance(dictAgents["groups"],list):
              strGroups = ""
              for dictGroup in dictAgents["groups"]:
                strGroups += dictGroup["name"] + ";"
              strGroups = strGroups[:-1]
            else:
              strGroups = dictAgents["groups"]
          else:
            strGroups = ""

          objFileOut.write("{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(strID,
                  strUUID,strName,strPlatform, strDistro, strIP, strPluginID, strCoreBuild,
                  strCoreVer,dtLinked,dtConnect,strStatus,strGroups))
          print ("{} {} {} {} done".format(strName,strPlatform,strDistro,strIP))
          iTotalProcessed+=1
      else:
        LogEntry("Agent list isn't a list???? "
          "Agent list is a {}".format(type(APIResponse["agents"])))
    else:
      LogEntry("No Agents in results, "
        "here are the first 99 character of the response: {}".format(APIResponse[99:]))

    if "pagination" in APIResponse:
      if "total" in APIResponse["pagination"]:
        iTotalAgents = APIResponse["pagination"]["total"]
      else:
        LogEntry("No total in pagination, something is horrible wrong")
        iOffset += iLimit
      if "offset" in APIResponse["pagination"]:
        iROffset = APIResponse["pagination"]["offset"]
      else:
        LogEntry("No offset in pagination, weird")
      if "limit" in APIResponse["pagination"]:
        iRLimit = APIResponse["pagination"]["limit"]
      else:
        LogEntry("No limit in pagination, weird")
    else:
      LogEntry("No pagination, must be done")
      iTotalAgents = iTotalProcessed
    LogEntry ("total: {}, offset:{}, limit{}".format(iTotalAgents,iROffset,iRLimit))
    iOffset += iLimit

  LogEntry("Results have been saved to {}".format(strFileout))
  LogEntry ("Completed {} rows at {}".format(iTotalProcessed,dtNow))
  tStop = time.time()
  iElapseSec = tStop - tStart - iTotalSleep
  iMin, iSec = divmod(iElapseSec, 60)
  iHours, iMin = divmod(iMin, 60)
  LogEntry ("Took {0:.2f} seconds to complete, "
    "which is {1} hours, {2} minutes and {3:.2f} seconds.".format(
              iElapseSec,iHours,iMin,iSec))

  SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
  objLogOut.close()
  objFileOut.close()

if __name__ == '__main__':
    main()

