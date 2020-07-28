'''
Tenable workbench download API Script
Author Siggi Bjarnason Copyright 2020

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

requests.urllib3.disable_warnings()

tLastCall = 0
iTotalSleep = 0

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

def FormatTenableDate (strdate):
  if strdate is None:
    return "None"
  if len(strdate) > 14:
    return strdate[:4] + "-" + strdate[4:6] + "-"+strdate[6:8] + " " + strdate[9:11] + ":" + strdate[11:13] + ":" + strdate[13:]
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
    LogEntry ("It has been less than {} seconds since last API call, "
      "waiting {} seconds".format(iMinQuiet,iAddWait))
    iTotalSleep += iAddWait
    time.sleep(iAddWait)
  iErrCode = ""
  iErrText = ""

  # LogEntry ("Doing a {} to URL: \n {}\n".format(strMethod,strURL))
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
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit ("due to issue with API, please check the logs")

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
    return "There was a problem with your request. Error {}: {}".format(iErrCode,iErrText)
  else:
    try:
      return WebRequest.json()
    except Exception as err:
      LogEntry ("Issue with converting response to json. "
        "Here are the first 99 character of the response: {}".format(WebRequest.text[:99]))

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
  global iMinQuiet
  global iTimeOut

  #Define few things
  iTimeOut = 120 # Max time in seconds to wait for network response
  iMinQuiet = 2 # Minimum time in seconds between API calls
  iSecSleep = 60 # Time to wait between check if ready
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")

  dictParams = {}
  dictParams["format"] = "csv"

  strFormat = "%Y-%m-%dT%H:%M:%S"
  strFileout = None
  bNotifyEnabled = False

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

  print ("This is a script to download results of a Tenable workbench query via API. "
    "This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)
  objFileOut = None

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

  if "ReportType" in dictConfig:
    dictParams["report"] = dictConfig["ReportType"]

  if "ReportChapter" in dictConfig:
    dictParams["chapter"] = dictConfig["ReportChapter"]

  if "DateRange" in dictConfig:
    dictParams["date_range"] = dictConfig["DateRange"]

  if "PluginID" in dictConfig:
    if dictConfig["PluginID"] != "":
      dictParams["plugin_ID"] = dictConfig["PluginID"]

  if "AssetID" in dictConfig:
    if dictConfig["AssetID"] != "":
      dictParams["asset_id"] = dictConfig["AssetID"]
  
  if "FilterType" in dictConfig:
    dictParams["filter.search_type"] = dictConfig["FilterType"]
  
  if "FilterDefFile" in dictConfig:
    strFilterFile = dictConfig["FilterDefFile"]
    LogEntry ("Processing Filter Definition file: {}".format(strFilterFile))
    strFilterFile = strFilterFile.replace("\\","/")
    if strFilterFile[:1] == "/" or strFilterFile[1:3] == ":/":
      LogEntry("File is absolute path, using as is")
    else:
      strFilterFile = strBaseDir + strFilterFile
      LogEntry("file is relative path,"
        " appended base directory. {}".format(strFilterFile))
    if os.path.isfile(strFilterFile):
      LogEntry ("file is valid")
      objFilterFile = open(strFilterFile,"r")
      lstFilterDefs = objFilterFile.readlines()
      objFilterFile.close()
    else:
      LogEntry ("invalid file in include directive")
    
    iIndex = 0
    for strFilterDef in lstFilterDefs:
      lstLineParts = strFilterDef.split(",")
      strIndex = "filter.{}.quality".format(iIndex)
      dictParams[strIndex] = lstLineParts[1]
      strIndex = "filter.{}.filter".format(iIndex)
      dictParams[strIndex] = lstLineParts[0]
      strIndex = "filter.{}.value".format(iIndex)
      dictParams[strIndex] = lstLineParts[2]
      iIndex += 1

  LogEntry ("Parameters: {}".format(dictParams))

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

  strMethod = "get"
  strAPIFunction = "workbenches/export"
  strParams = urlparse.urlencode(dictParams)
  strURL = strBaseURL + strAPIFunction + "?" + strParams
  LogEntry("Submitting query request\n {} {}\n Payload{}".format(strMethod, strURL,dictPayload))
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  # APIResponse = {"file":268445459}
  if "file" in APIResponse:
    LogEntry ("FileID={}".format(APIResponse["file"]))
    iFileID = APIResponse["file"]
  else:
    LogEntry ("Unepxected results: {}".format(APIResponse),True)

  LogEntry ("Giving the download {} seconds to generate.".format(iSecSleep))
  time.sleep(iSecSleep)
  LogEntry ("Checking the status of the download...")
  bFinished = False
  while not bFinished:
    strURL = strBaseURL + strAPIFunction + "/" + str(iFileID) + "/status"
    APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
    if "status" in APIResponse:
      if APIResponse["status"] == "ready":
        bFinished = True
        LogEntry ("Download is ready.")
      else:
        if "progress" in APIResponse:
          iProgress = float(APIResponse["progress"])
        else:
          iProgress = 0
        if "progress_total" in APIResponse:
          iJobTotal = float(APIResponse["progress_total"])
        else:
          iJobTotal = 0
        if iJobTotal > 0 and iJobTotal > iProgress:
          fPercentage = iProgress / iJobTotal
        else:
          fPercentage = 0
        if fPercentage == 0:
          LogEntry ("{} {} / {} ".format(APIResponse["status"],APIResponse["progress"],APIResponse["progress_total"]))
        else:
          LogEntry ("{} {:.3%} complete".format(APIResponse["status"],fPercentage))
        time.sleep(iSecSleep)

  strURL = strBaseURL + strAPIFunction + "/" + str(iFileID) + "/download"

  LogEntry ("Doing a stream GET to URL: \n {}\n".format(strURL))
  try:
    WebRequest = requests.get(strURL, headers=strHeader, stream=True)
    LogEntry ("get executed")
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err),True)

  if isinstance(WebRequest,requests.models.Response)==False:
    LogEntry ("response is unknown type",True)
 # end if
  LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
  LogEntry ("Starting to stream the results to disk")
  iLineNum = 1
  try:
    for strLine in WebRequest.iter_lines():
      if strLine:
        strLine = strLine.decode("ascii","ignore")
        print ("Downloaded {} lines.".format(iLineNum),end="\r")
        iLineNum += 1
        objFileOut.write ("{}\n".format(strLine))
  except Exception as err:
    LogEntry ("Unexpected issue: {}".format(err),True)

  objFileOut.close()
  LogEntry ("Done!")
  objLogOut.close()

if __name__ == '__main__':
    main()

