'''
Tenable Asset Export to DB API Script
Author Siggi Bjarnason Copyright 2020

Following packages need to be installed as administrator
pip install requests
pip install jason
pip install pymysql

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
import pymysql
# End imports

#avoid insecure warning
requests.urllib3.disable_warnings()

#Define few things
iChunkSize = 5000
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
iTotalSleep = 0
tLastCall = 0

def Date2DB(strDate):
  strTemp = DBClean(strDate)
  strTemp = strTemp.replace("T"," ")
  return strTemp.replace("Z","")

def SQLConn(strServer, strDBUser, strDBPWD, strInitialDB):
  try:
    # Open database connection
    return pymysql.connect(strServer, strDBUser, strDBPWD, strInitialDB)
  except pymysql.err.InternalError as err:
    print("Error: unable to connect: {}".format(err))
    sys.exit(5)
  except pymysql.err.OperationalError as err:
    print("Operational Error: unable to connect: {}".format(err))
    sys.exit(5)
  except pymysql.err.ProgrammingError as err:
    print("Programing Error: unable to connect: {}".format(err))
    sys.exit(5)

def SQLQuery(strSQL, db):
  try:
    # prepare a cursor object using cursor() method
    dbCursor = db.cursor()
    # Execute the SQL command
    dbCursor.execute(strSQL)
    # Count rows
    iRowCount = dbCursor.rowcount
    if strSQL[:6].lower() == "select" or strSQL[:4].lower() == "call":
      dbResults = dbCursor.fetchall()
    else:
      db.commit()
      dbResults = ()
    return [iRowCount, dbResults]
  except pymysql.err.InternalError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Internal Error: unable to execute: {}\n{}".format(err, strSQL)
  except pymysql.err.ProgrammingError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Programing Error: unable to execute: {}\n{}".format(err, strSQL)
  except pymysql.err.OperationalError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Programing Error: unable to execute: {}\n{}".format(err, strSQL)
  except pymysql.err.IntegrityError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Integrity Error: unable to execute: {}\n{}".format(err, strSQL)
  except pymysql.err.DataError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Data Error: unable to execute: {}\n{}".format(err, strSQL)

def ValidReturn(lsttest):
  if isinstance(lsttest, list):
    if len(lsttest) == 2:
      if isinstance(lsttest[0], int) and isinstance(lsttest[1], tuple):
        return True
      else:
        return False
    else:
      return False
  else:
    return False

def DBClean(strText):
  if strText is None:
    return ""
  else:
    strTemp = strText.encode("ascii", "ignore")
    strTemp = strTemp.decode("ascii", "ignore")
    strTemp = strTemp.replace("\\", "\\\\")
    strTemp = strTemp.replace("'", "\\'")
    return strTemp

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
  if not bNotifyEnabled:
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
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    CleanExit ("due to issue with API, please check the logs")

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

def FetchChunks(strFunction,lstChunks, strExportUUID):

  global iRowCount
  global dictChunkStatus

  strAPIFunction = strFunction + "/export/"

  for iChunkID in lstChunks:
    if iChunkID in dictChunkStatus:
      LogEntry  ("Already processed chunk # {}, skipping".format(iChunkID))
      continue

    strURL = strBaseURL + strAPIFunction + strExportUUID + "/chunks/" + str(iChunkID)
    APIResponse = MakeAPICall(strURL,strHeader,"get")

    if isinstance(APIResponse,str):
      LogEntry(APIResponse,True)
      break
    elif isinstance(APIResponse,dict):
      LogEntry ("response is a dict")
    elif isinstance(APIResponse,list):
      iChunkLen = len(APIResponse)
      iRowCount += iChunkLen
      dictChunkStatus[iChunkID] = iChunkLen
      LogEntry  ("Downloaded {0} {1} for chunk {2}. Total {3} {1} downloaded so far.".format(iChunkLen, strFunction, iChunkID,iRowCount))
      for dictChunkItem in APIResponse:
        if "id" in dictChunkItem:
          strAssetID = "'" + DBClean(dictChunkItem["id"]) + "'"
        else:
          strAssetID = "''"
        if "has_agent" in dictChunkItem:
          if dictChunkItem["has_agent"] == True:
            bHasAgent = True
          else:
            bHasAgent = False
        else:
          bHasAgent = "NULL"
        if "created_at" in dictChunkItem:
          dtCreated = "'" + Date2DB (dictChunkItem["created_at"]) + "'"
        else:
          dtCreated = "''"
        if "updated_at" in dictChunkItem:
          dtUpdated = "'" + Date2DB (dictChunkItem["updated_at"]) + "'"
        else:
          dtUpdated = "''"
        if "first_seen" in dictChunkItem:
          dt1stSeen = "'" + Date2DB (dictChunkItem["first_seen"]) + "'"
        else:
          dt1stSeen = "''"
        if "last_seen" in dictChunkItem:
          dtLastSeen = "'" + Date2DB (dictChunkItem["last_seen"]) + "'"
        else:
          dtLastSeen = "''"
        if "first_scan_time" in dictChunkItem:
          dtFirstScan = "'" + Date2DB (dictChunkItem["first_scan_time"]) + "'"
        else:
          dtFirstScan = "''"
        if "last_scan_time" in dictChunkItem:
          dtLastScan = "'" + Date2DB (dictChunkItem["last_scan_time"]) + "'"
        else:
          dtLastScan = "''"
        if "last_authenticated_scan_date" in dictChunkItem:
          dtLastAuthScan = "'" + Date2DB (dictChunkItem["last_authenticated_scan_date"]) + "'"
        else:
          dtLastAuthScan = "''"
        if "last_licensed_scan_date" in dictChunkItem:
          dtLastLicensedScan = "'" + Date2DB (dictChunkItem["last_licensed_scan_date"]) + "'"
        else:
          dtLastLicensedScan = "''"
        if "agent_uuid" in dictChunkItem:
          strAgentUUID = "'" + DBClean (dictChunkItem["agent_uuid"]) + "'"
        else:
          strAgentUUID = "''"
        if "bios_uuid" in dictChunkItem:
          strBIOSid = "'" + DBClean (dictChunkItem["bios_uuid"]) + "'"
        else:
          strBIOSid = "''"
        if "agent_names" in dictChunkItem:
          strAgentNames = "'" + DBClean (" | ".join(dictChunkItem["agent_names"])) + "'"
        else:
          strAgentNames = "''"
        if "ipv4s" in dictChunkItem:
          strIPv4 = "'" + DBClean (" | ".join(dictChunkItem["ipv4s"])) + "'"
        else:
          strIPv4 = "''"
        if "ipv6s" in dictChunkItem:
          strIPv6 = "'" + DBClean (" | ".join(dictChunkItem["ipv6s"])) + "'"
        else:
          strIPv6 = "''"
        if "fqdns" in dictChunkItem:
          strFQDNs = "'" + DBClean (" | ".join(dictChunkItem["fqdns"])) + "'"
        else:
          strFQDNs = "''"
        if "mac_addresses" in dictChunkItem:
          strMACAddr = "'" + DBClean (" | ".join(dictChunkItem["mac_addresses"])) + "'"
        else:
          strMACAddr = "''"
        if "netbios_names" in dictChunkItem:
          strNetBIOS = "'" + DBClean (" | ".join(dictChunkItem["netbios_names"])) + "'"
        else:
          strNetBIOS = "''"
        if "operating_systems" in dictChunkItem:
          strOS = "'" + DBClean (" | ".join(dictChunkItem["operating_systems"])) + "'"
        else:
          strOS = "''"
        if "hostnames" in dictChunkItem:
          strHostName = "'" + DBClean (" | ".join(dictChunkItem["hostnames"])) + "'"
        else:
          strHostName = "''"

        strSQL = ("INSERT INTO VulnMgmt.TnblAssets (vcAssetID, bHasAgent, dtCreated, dtUpdated,"
                  " dt1stSeen, dtLastSeen, dtFirstScan, dtLastScan, dtLastAuthScan, dtLastLicensedScan,"
                  " vcAgentUUID, vcBIOSid, vcAgentName, vcIPv4s, vcIPv6s, vcFQDNs, vcMACAddr,"
                  " vcNetbiosNames, vcOS, vcHostNames)"
                  " VALUES({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, "
                  " {}, {}, {}, {}, {});".format(strAssetID,bHasAgent,dtCreated,dtUpdated,dt1stSeen,
                  dtLastSeen,dtFirstScan,dtLastScan,dtLastAuthScan,dtLastLicensedScan,strAgentUUID,
                  strBIOSid,strAgentNames,strIPv4,strIPv6,strFQDNs,strMACAddr,strNetBIOS,strOS,
                  strHostName))
        lstReturn = SQLQuery(strSQL, dbConn)
        if not ValidReturn(lstReturn):
          LogEntry("Unexpected: {}".format(lstReturn))
          CleanExit("due to unexpected SQL return, please check the logs")
        elif lstReturn[0] != 1:
          LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))


def CleanStr(strOld):
  strTemp = strOld.replace('"','')
  strTemp = strTemp.replace(',','')
  strTemp = strTemp.replace('\n','')
  return strTemp.strip()

def BulkExport(strFunction):

  global iRowCount

  iRowCount = 0
  iTotalSleep = 0
  tStart=time.time()
  dictResults = {}

  strAPIFunction = strFunction + "/export/"

  strStatus = "PROCESSING"
  iChunkCount = 0
  lstChunks = []
  
  strURL = strBaseURL + strAPIFunction

  APIResponse = MakeAPICall(strURL,strHeader,"post", dictPayload)
  if isinstance(APIResponse,str):
    LogEntry(APIResponse,True)
  elif isinstance(APIResponse,dict):
    strExportUUID = APIResponse['export_uuid']
    LogEntry ("Export successfully requested. Confirmation UUID {}".format(strExportUUID))
    strURL = strBaseURL + strAPIFunction + strExportUUID + "/status"
    while strStatus == "PROCESSING":
      APIResponse = MakeAPICall(strURL,strHeader,"get")
      if isinstance(APIResponse,str):
        LogEntry(APIResponse,True)
        strStatus = "Error"
      elif isinstance(APIResponse,dict):
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
        LogEntry ("Status: {} | Chunks Available: {}".format(strStatus,iChunkCount))
        if iChunkCount > 0:
          LogEntry ("Available Chunks: {}".format(lstChunks))
          lstNotProcessed = []
          for iChunkID in lstChunks:
            if iChunkID not in dictChunkStatus:
              lstNotProcessed.append(iChunkID)
          if len(lstNotProcessed) > 0:
            LogEntry("Now fetching chunks {}".format(lstNotProcessed))
            FetchChunks(strFunction,lstNotProcessed,strExportUUID)

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
  global iLoc
  global iMinQuiet
  global iRowCount
  global iTimeOut
  global iTotalSleep
  global objLogOut
  global strBaseDir
  global strBaseURL
  global strFormat
  global strNotifyChannel
  global strNotifyToken
  global strNotifyURL
  global strScriptHost
  global strScriptName
  global tLastCall
  global tStart
  global strHeader
  global dictChunkStatus
  global dictDur
  global dictCount
  global dbConn

  strNotifyToken = None
  strNotifyChannel = None
  strNotifyURL = None
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  iRowCount = 0
  tStart=time.time()

  dictChunkStatus = {}
  dictFilter = {}
  dictPayload = {}
  dictDur = {}
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

  print ("This is a script to download Tenable Asset information via API and write to DB. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)
  
  dictConfig = processConf(strConf_File)

  if "Filter" in dictConfig:
    lstStrParts = dictConfig["Filter"].split(":")
    for strFilter in lstStrParts:
      lstFilterParts = strFilter.split("|")
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

  if "dbUser" in dictConfig:
    strDBUser = dictConfig["dbUser"]
  else:
    LogEntry("No DB UserID",True)

  if "dbPWD" in dictConfig:
    strDBPWD = dictConfig["dbPWD"]
  else:
    LogEntry("No DB PWD",True)

  if "Server" in dictConfig:
    strServer = dictConfig["Server"]
  else:
    LogEntry("No DB Server",True)

  if "InitialDB" in dictConfig:
    strInitialDB = dictConfig["InitialDB"]
  else:
    LogEntry("No Initial DB",True)

  strSQL = "TRUNCATE VulnMgmt.TnblAssets;"
  dbConn = SQLConn(strServer, strDBUser, strDBPWD, strInitialDB)
  lstReturn = SQLQuery(strSQL, dbConn)
  if not ValidReturn(lstReturn):
    LogEntry("Unexpected: {}".format(lstReturn))
    CleanExit("due to unexpected SQL return, please check the logs")
  else:
    LogEntry("Truncated VulnMgmt.TnblAssets")

  dictPayload["num_assets"] = iChunkSize
  dictPayload["filters"] = dictFilter

  dictResults={}
  dictResults = BulkExport ("assets")
  
  LogEntry ("Downloaded {} vulns".format(dictResults["RowCount"]))
  LogEntry ("Took {0:.2f} seconds to complete, which is {1} hours, {2} minutes and {3:.2f} seconds.".format(
    dictResults["Elapse"],int(dictResults["hours"]),
    int(dictResults["min"]),dictResults["Sec"]))

  LogEntry ("Completed at {}".format(dtNow))
  SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
  objLogOut.close()

if __name__ == '__main__':
  main()
