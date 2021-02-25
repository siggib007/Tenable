'''
Tenable Scan List API Script
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

#Define few things
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")



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

def CleanExit(strCause):
  objLogOut.close()
  print ("objLogOut closed")
  if objFileOut is not None:
    objFileOut.close()
    print ("objFileOut closed")
  else:
    print ("objFileOut is not defined yet")
  if objHistory is not None:
    objHistory.close()
    print ("objHistory closed")
  else:
    print ("objHistory is not defined yet")
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
    CleanExit("")

# def processConf():
#   global strBaseURL
#   global strUserName
#   global strPWD
#   global strNotifyURL
#   global strNotifyToken
#   global strNotifyChannel
#   global strHeader
#   global strFormat
#   global strFileout
#   global bNotifyEnabled

#   strBaseURL=None
#   strUserName=None
#   strPWD=None
#   strNotifyURL=None
#   strNotifyToken=None
#   strNotifyChannel=None
#   strHeader=None
#   strFormat="%Y-%m-%dT%H:%M:%S"
#   strFileout=None

#   LogEntry ("Looking for configuration file: {}".format(strConf_File))
#   if os.path.isfile(strConf_File):
#     LogEntry ("Configuration File exists")
#   else:
#     LogEntry ("Can't find configuration file {}, make sure it is the same directory as this script".format(strConf_File))
#     LogEntry("{} on {}: Exiting.".format (strScriptName,strScriptHost))
#     objLogOut.close()
#     sys.exit(9)

#   strLine = "  "
#   LogEntry ("Reading in configuration")
#   objINIFile = open(strConf_File,"r")
#   strLines = objINIFile.readlines()
#   objINIFile.close()

#   for strLine in strLines:
#     strLine = strLine.strip()
#     iCommentLoc = strLine.find("#")
#     if iCommentLoc > -1:
#       strLine = strLine[:iCommentLoc].strip()
#     else:
#       strLine = strLine.strip()
#     if "=" in strLine:
#       strConfParts = strLine.split("=")
#       strVarName = strConfParts[0].strip()
#       strValue = strConfParts[1].strip()
#       strConfParts = strLine.split("=")
#       if strVarName == "APIBaseURL":
#         strBaseURL = strValue
#       if strVarName == "AccessKey":
#         strUserName = strValue
#       if strVarName == "Secret":
#         strPWD = strValue
#       if strVarName == "NotificationURL":
#         strNotifyURL = strValue
#       if strVarName == "NotifyChannel":
#         strNotifyChannel = strValue
#       if strVarName == "NotifyToken":
#         strNotifyToken = strValue
#       if strVarName == "DateTimeFormat":
#         strFormat = strValue
#       if strVarName == "OutFile":
#         strFileout = strValue

#   strHeader={'Content-type':'application/json','X-ApiKeys':'accessKey='+strUserName+';secretKey='+strPWD}
#   if strNotifyToken is None or strNotifyChannel is None or strNotifyURL is None:
#     bNotifyEnabled = False
#     LogEntry("Missing configuration items for Slack notifications, turning slack notifications off")
#   else:
#     bNotifyEnabled = True

#   if strBaseURL[-1:] != "/":
#     strBaseURL += "/"

#   LogEntry ("Done processing configuration, moving on")

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
    return strdate[:4]+"-"+strdate[4:6]+"-"+strdate[6:8]+" "+strdate[9:11]+":"+strdate[11:13]+":"+strdate[13:]
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
    LogEntry ("It has been less than {} seconds since last API call, waiting {} seconds".format(iMinQuiet,iAddWait))
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
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    try:
      return WebRequest.json()
    except Exception as err:
      LogEntry ("Issue with converting response to json. Here are the first 99 character of the response: {}".format(WebRequest.text[:99]))


def main():
  global strFileout
  global objFileOut
  global objHistory
  global objLogOut
  global strConf_File
  global strScriptName
  global strScriptHost
  global tLastCall
  global iTotalSleep

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
  if strScriptHost == "DEV-APS-RHEL-STD-A":
    strScriptHost = "VMSAWS01"

  print ("This is a script to download Scan job history information via API. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)
  objFileOut = None
  objHistory = None

  dictConfig = processConf(strConf_File)

  if "APIBaseURL" in dictConfig:
    strBaseURL = dictConfig["APIBaseURL"]
  else:
    LogEntry("APIBaseURL not provided")
  if "AccessKey" in dictConfig:
    strUserName = dictConfig["AccessKey"]
    strHeader={
    'Content-type':'application/json',
    'X-ApiKeys':'accessKey=' + dictConfig["AccessKey"] + ';secretKey=' + dictConfig["Secret"]}
  else:
    LogEntry("AccessKey not provided")
  if "Secret" in dictConfig:
    strPWD = dictConfig["Secret"]
  else:
    LogEntry("Secret not provided")
  if "NotificationURL" in dictConfig:
    strNotifyURL = dictConfig["NotificationURL"]
  else:
    LogEntry("NotificationURL not provided")
  if "NotifyChannel" in dictConfig:
    strNotifyChannel = dictConfig["NotifyChannel"]
  else:
    LogEntry("NotifyChannel not provided")
  if "NotifyToken" in dictConfig:
    strNotifyToken = dictConfig["NotifyToken"]
  else:
    LogEntry("NotifyToken not provided")
  if "DateTimeFormat" in dictConfig:
    strFormat = dictConfig["DateTimeFormat"]
  else:
    LogEntry("DateTimeFormat not provided")
  if "OutFile" in dictConfig:
    strFileout = dictConfig["OutFile"]
  else:
    LogEntry("OutFile not provided")


  if "NotifyToken" in dictConfig and "NotifyChannel" in dictConfig and "NotificationURL" in dictConfig:
    bNotifyEnabled = True
  else:
    bNotifyEnabled = False
    LogEntry("Missing configuration items for Slack notifications, "
      "turning slack notifications off")

  tLastCall = 0
  iTotalSleep = 0
  tStart=time.time()
  # processConf()
  dictResults={}
  strAPIFunction = "scans"
  strMethod = "get"
  if strFileout is None or strFileout =="":
    LogEntry("outfile not define, using defaults")
    strFileout = strOutDir + strScriptName[:iLoc] + "-" + strFunction + ISO + ".csv"
  else:
    if not os.path.exists(os.path.dirname(strFileout)):
      LogEntry ("\nPath '{0}' for output files didn't exists, so I'm creating it!\n".format(strFileout))
      os.makedirs(os.path.dirname(strFileout))
  LogEntry ("Output will be written to {}".format(strFileout))

  try:
    objFileOut = open(strFileout,"w")
  except PermissionError:
    LogEntry("unable to open output file {} for writing, permission denied.".format(strFileout),True)

  objFileOut.write("Name,status,enabled?,created on,last modified,timezone,Recurrance Rules,start time,")
  objFileOut.write("Scanner,policy,host count,scan start,scan end,elapse seconds,Duration,seconds per host\n")

  strHistoryPath = os.path.dirname(strFileout)
  strHistoryPath = strHistoryPath.replace("\\","/")
  if strHistoryPath[-1:] != "/":
    strHistoryPath += "/"
  iLoc = strScriptName.rfind(".")
  strHistoryPath = strHistoryPath + strScriptName[:iLoc] + "-history"
  if strHistoryPath[-1:] != "/":
    strHistoryPath += "/"
  LogEntry ("writing history to {}".format(strHistoryPath))
  if not os.path.exists (strHistoryPath) :
    os.makedirs(strHistoryPath)
    LogEntry ("\nPath '{0}' for history files didn't exists, so I create it!\n".format(strHistoryPath))

  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if "scans" in APIResponse:
    if isinstance(APIResponse["scans"],list):
      for dictScan in APIResponse["scans"]:
        objFileOut.write("{},{},{},{},{},{},\"{}\",{},".format(dictScan["name"],dictScan["status"],dictScan["enabled"],
                formatUnixDate(dictScan["creation_date"]), formatUnixDate (dictScan["last_modification_date"]),
                dictScan["timezone"],dictScan["rrules"],FormatTenableDate(dictScan["starttime"])))
        strURL = strBaseURL + strAPIFunction + "/" + dictScan["schedule_uuid"]
        APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
        if isinstance(APIResponse,dict):
          if "info" in APIResponse:
            dictScan = APIResponse["info"]
            if "scan_end" in dictScan and "scan_start" in dictScan:
              strScanEnd = formatUnixDate(dictScan["scan_end"])
              strScanStart = formatUnixDate(dictScan["scan_start"])
              iElapse = dictScan["scan_end"]-dictScan["scan_start"]
              iMin, iSec = divmod(iElapse, 60)
              iHours, iMin = divmod(iMin, 60)
              iDay,iHours = divmod(iHours,24)
              strDuration = "{0} days {1} hours {2} minutes and {3} seconds.".format(iDay,iHours,iMin,iSec)
            else:
              iElapse = 0
              iMin = 0
              iSec = 0
              iHours = 0
              iDay = 0
              strDuration = "End or start not defined"
              if "scan_end" in dictScan:
                strScanEnd = formatUnixDate(dictScan["scan_end"])
              else:
                strScanEnd = "None"
              if "scan_start" in dictScan:
                strScanStart = formatUnixDate(dictScan["scan_start"])
              else:
                strScanStart = "None"

            objFileOut.write("{},{},{},{},{},{},{},{}\n".format(dictScan["scanner_name"],
                dictScan["policy"],dictScan["hostcount"],strScanStart,
                strScanEnd,iElapse,strDuration,iElapse/dictScan["hostcount"]))
            strHistoryOut = strHistoryPath+dictScan["name"].replace("/", "-")+".csv"
            try:
              objHistory = open(strHistoryOut ,"w")
            except PermissionError:
              LogEntry("unable to open output file {} for writing, permission denied.".format(strHistoryOut),True)
            objHistory.write("name,status,start,stop,elapse,duration\n")
            for dictHistID in APIResponse["history"]:
              strURL = strBaseURL + strAPIFunction + "/" + dictScan["schedule_uuid"] + "/history/" + str(dictHistID["history_id"])
              APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
              if isinstance(APIResponse,dict):
                iElapse = APIResponse["scan_end"]-APIResponse["scan_start"]
                iMin, iSec = divmod(iElapse, 60)
                iHours, iMin = divmod(iMin, 60)
                iDay,iHours = divmod(iHours,24)
                strDuration = "{0} days {1} hours {2} minutes and {3} seconds.".format(
                                 iDay,iHours,iMin,iSec)
                objHistory.write("{},{},{},{},{},{}\n".format(APIResponse["name"],APIResponse["status"],
                    formatUnixDate(APIResponse["scan_start"]),formatUnixDate(APIResponse["scan_end"]),
                    iElapse,strDuration))
              else:
                LogEntry("History API response not a dictionary. Here is the response: {}".format(APIResponse),True)
            objHistory.close()
          else:
            LogEntry("no info in dict details")
        else:
          LogEntry("Details response is {}".format(type(APIResponse)))
    else:
      LogEntry("Scanlist isn't a list???? Scanlist is a {}".format(type(APIResponse["scans"])))
  else:
    LogEntry("No scan in results, here are the first 99 character of the response: {}".format(APIResponse[99:]))


  LogEntry("Results have been saved to {}".format(strFileout))
  LogEntry ("Completed at {}".format(dtNow))
  tStop = time.time()
  iElapseSec = tStop - tStart - iTotalSleep
  iMin, iSec = divmod(iElapseSec, 60)
  iHours, iMin = divmod(iMin, 60)
  LogEntry ("Took {0:.2f} seconds to complete, which is {1} hours, {2} minutes and {3:.2f} seconds.".format(
              iElapseSec,iHours,iMin,iSec))

  objLogOut.close()
  objFileOut.close()

if __name__ == '__main__':
    main()

