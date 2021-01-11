'''
Tenable Scanner List API Script
Author Siggi Bjarnason Copyright 2019

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
import pymysql
# End imports

#avoid insecure warning
requests.urllib3.disable_warnings()

#Define few defaults
iTimeOut = 120
iSlackLimit = 950
iMinQuiet = 2 # Minimum time in seconds between API calls
ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")

#Initialize couple of variables
tLastCall = None
iTotalSleep = None


def SendNotification (strMsg):
  LogEntry ("{}".format(strMsg))
  if not bNotifyEnabled:
    LogEntry ("notify not enabled")
    return
  strMsg = strScriptName + ": " + strMsg
  dictNotify = {}
  dictNotify["token"] = dictConfig["NotifyToken"]
  dictNotify["channel"] = dictConfig["NotifyChannel"]
  dictNotify["text"]=strMsg[:iSlackLimit]
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
        LogEntry ("Successfully sent slack notification")
    if not bStatus or WebRequest.status_code != 200:
      LogEntry ("Problem: Status Code:[] API Response OK={}")
      LogEntry (WebRequest.text)

def CleanExit(strCause):
  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  print ("objLogOut closed")
  sys.exit(9)

def LogEntry(strMsg,bAbort=False):
  strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
  objLogOut.write("{0} : {1}\n".format(strTimeStamp,strMsg))
  print (strMsg)
  if bAbort:
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
  strTemp = str(strText)
  strTemp = strTemp.encode("ascii","ignore")
  strTemp = strTemp.decode("ascii","ignore")
  strTemp = strTemp.replace("\\","\\\\")
  strTemp = strTemp.replace("'","\"")
  return strTemp

def getInput(strPrompt):
    if sys.version_info[0] > 2 :
        return input(strPrompt)
    else:
      print("Please upgrade to Python 3")
      sys.exit()

def SQLConn (strServer,strDBUser,strDBPWD,strInitialDB):
  try:
    # Open database connection
    return pymysql.connect(strServer,strDBUser,strDBPWD,strInitialDB)
  except pymysql.err.InternalError as err:
    print ("Error: unable to connect: {}".format(err))
    sys.exit(5)
  except pymysql.err.OperationalError as err:
    print ("Operational Error: unable to connect: {}".format(err))
    sys.exit(5)
  except pymysql.err.ProgrammingError as err:
    print ("Programing Error: unable to connect: {}".format(err))
    sys.exit(5)

def SQLQuery (strSQL,db):
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
    return [iRowCount,dbResults]
  except pymysql.err.InternalError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Internal Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.ProgrammingError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Programing Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.OperationalError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Programing Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.IntegrityError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Integrity Error: unable to execute: {}\n{}".format(err,strSQL)
  except pymysql.err.DataError as err:
    if strSQL[:6].lower() != "select":
      db.rollback()
    return "Data Error: unable to execute: {}\n{}".format(err,strSQL)

def ValidReturn(lsttest):
  if isinstance(lsttest,list):
    if len(lsttest) == 2:
      if isinstance(lsttest[0],int) and isinstance(lsttest[1],tuple):
        return True
      else:
        return False
    else:
      return False
  else:
    return False

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

  if WebRequest.text == "":
    return ""
  if iErrCode != "" or WebRequest.status_code !=200:
    return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code,iErrCode,iErrText)
  else:
    try:
      return WebRequest.json()
    except Exception as err:
      LogEntry ("Issue with converting response to json. Here are the first 99 character of the response: {}".format(WebRequest.text[:99]))

def ScannerDBUpdate(dictResults,dbConn):

  lstInvalidTypes = []
  dictStatusChange = {}
  dictStatusOff = {}
  if "scanners" in dictResults:
    if isinstance(dictResults["scanners"],list):
      for dictScan in dictResults["scanners"]:
        strScanIP = "'' "
        strScanType = "'' "
        iAltServerID = 0
        strAltSource = "'n/a'"
        strLocation = ""
        iScannerID = -9
        if "group" in dictScan:
          if dictScan["group"] == False:
            if "name" in dictScan:
              if dictScan["name"][-5:] == ".mgmt":
                strScannerName = "'{}'".format(DBClean(dictScan["name"][:-5]))
              else:
                strScannerName = "'{}'".format(DBClean(dictScan["name"]))
            else:
              strScannerName = "'Unknown Name' "
            if "id" in dictScan:
              iScannerID = "{}".format(DBClean(dictScan["id"]))
              if not isInt(iScannerID):
                LogEntry ("Scanner ID is not an integer, it is '{}'. "
                  " abort, abort abort.".format(iScannerID),True)
            else:
              iScannerID = "NULL"
            LogEntry("Scanner ID {} is called {}. ".format(iScannerID, strScannerName))
            strSQL = "select iServerID from tblServers where vcName = {};".format(strScannerName)
            lstReturn = SQLQuery (strSQL,dbConn)
            if not ValidReturn(lstReturn):
              LogEntry ("Unexpected: {}".format(lstReturn))
              CleanExit("due to unexpected SQL return, please check the logs")
            elif lstReturn[0] == 0:
              iServerID = -15
              LogEntry ("Server {} not in server table".format(strScannerName))
            elif lstReturn[0] > 1:
              SendNotification ("More than one instance of {} in server table,"
                " picking the first one".format(strScannerName))
              LogEntry ("More than one instance of {} in server table,"
                " picking the first one".format(strScannerName))
              iServerID = lstReturn[1][0][0]
            else:
              iServerID = lstReturn[1][0][0]
            LogEntry ("{} has ID of {}".format(strScannerName, iServerID))

            if iServerID == -15:
              strSQL = "select iMBServerID from tblMBServers where vcServerName = {};".format(strScannerName)
              lstReturn = SQLQuery (strSQL,dbConn)
              if not ValidReturn(lstReturn):
                LogEntry ("Unexpected: {}".format(lstReturn))
                CleanExit("due to unexpected SQL return, please check the logs")
              elif lstReturn[0] == 0:
                LogEntry ("Server {} not in MBserver table".format(strScannerName))
              elif lstReturn[0] > 1:
                SendNotification ("More than one instance of {} in MBserver table,"
                  " picking the first one".format(strScannerName))
                LogEntry ("More than one instance of {} in MBserver table,"
                  " picking the first one".format(strScannerName))
                iAltServerID = lstReturn[1][0][0]
                strAltSource = "'tblMBServers'"
              else:
                iAltServerID = lstReturn[1][0][0]
                strAltSource = "'tblMBServers'"

            if iServerID > 0:
              strSQL = "select vcLocCode from tblServers where iServerID = {};".format(iServerID)
              lstReturn = SQLQuery (strSQL,dbConn)
              if not ValidReturn(lstReturn):
                LogEntry ("Unexpected: {}".format(lstReturn))
                CleanExit("due to unexpected SQL return, please check the logs")
              elif lstReturn[0] == 0:
                strLocation = "Unknown"
                LogEntry ("Server {} with ID of {} not found in server table".format(strScannerName, iServerID))
                SendNotification ("Server {} with ID of {} not found in server table".format(strScannerName, iServerID))
              else:
                strLocation = lstReturn[1][0][0]
                LogEntry ("Location: {}".format(strLocation))

              strSQL = "select vcIPAddr, vcNetType from tblNICs where iServerID = {};".format(iServerID)
              lstReturn = SQLQuery (strSQL,dbConn)
              if not ValidReturn(lstReturn):
                LogEntry ("Unexpected: {}".format(lstReturn))
                CleanExit("due to unexpected SQL return, please check the logs")
              elif lstReturn[0] == 0:
                strLocation = "Unknown"
                LogEntry ("Server {} with ID of {} has no entries in the NIC table".format(strScannerName, iServerID))
              elif lstReturn[0] == 1:
                strScanIP = "'{}'".format(lstReturn[1][0][0])
                strScanType = "'{}'".format(lstReturn[1][0][1].lower())
              else:
                for dbRow in lstReturn[1]:
                  if lstReturn[0] == 2:
                    if dbRow[1] != "EIT":
                      strScanIP = "'{}'".format(dbRow[0])
                      strScanType = "'{}'".format(dbRow[1].lower())
                  if lstReturn[0] == 3:
                    if dbRow[1] != "EIT" and dbRow[1] != "NMnet":
                      strScanIP = "'{}'".format(dbRow[0])
                      strScanType = "'{}'".format(dbRow[1].lower())
            elif iAltServerID > 0:
              strSQL = "select vcSite from tblMBServers where iMBServerID = {};".format(iAltServerID)
              lstReturn = SQLQuery (strSQL,dbConn)
              if not ValidReturn(lstReturn):
                LogEntry ("Unexpected: {}".format(lstReturn))
                CleanExit("due to unexpected SQL return, please check the logs")
              elif lstReturn[0] == 0:
                strLocation = "Unknown"
                LogEntry ("Server {} with ID of {} not found in MBserver table".format(strScannerName, iAltServerID))
                SendNotification ("Server {} with ID of {} not found in MBserver table".format(strScannerName, iAltServerID))
              else:
                strLocation = lstReturn[1][0][0]
                LogEntry ("Location: {}".format(strLocation))

              strSQL = "select vcIPaddr, vcNetwork from tblMBNICs where iMBServerID = {};".format(iAltServerID)
              lstReturn = SQLQuery (strSQL,dbConn)
              if not ValidReturn(lstReturn):
                LogEntry ("Unexpected: {}".format(lstReturn))
                CleanExit("due to unexpected SQL return, please check the logs")
              elif lstReturn[0] == 0:
                strLocation = "Unknown"
                LogEntry ("Server {} with ID of {} not found in server table".format(strScannerName, iAltServerID))
                SendNotification ("Server {} with ID of {} not found in server table".format(strScannerName, iAltServerID))
              elif lstReturn[0] == 1:
                strScanIP = "'{}'".format(lstReturn[1][0][0])
                strScanType = "'{}'".format(lstReturn[1][0][1])
              else:
                for dbRow in lstReturn[1]:
                  strTempType = dbRow[1]
                  iLoc = strTempType.find("-")
                  strTempType = strTempType[:iLoc].lower()
                  if lstReturn[0] == 2:
                    if strTempType != "eit":
                      strScanIP = "'{}'".format(dbRow[0])
                      strScanType = "'{}'".format(strTempType)
                  if lstReturn[0] == 3:
                    if strTempType != "eit" and strTempType != "nmnet":
                      strScanIP = "'{}'".format(dbRow[0])
                      strScanType = "'{}'".format(strTempType)
                  if lstReturn[0] == 4:
                    if strTempType != "eit" and strTempType != "nmnet" and strTempType != "corenet6":
                      strScanIP = "'{}'".format(dbRow[0])
                      strScanType = "'{}'".format(strTempType)
            if "ip_addresses" in dictScan:
              if isinstance(dictScan["ip_addresses"],list):
                strIPList = "'{}'".format(" | ".join(dictScan["ip_addresses"]))
              else:
                strIPList = "NULL"
            else:
              strIPList = "NULL"        
            if "creation_date" in dictScan:
              strCreateddt = "'{}'".format(formatUnixDate(dictScan["creation_date"]))
            else:
              strCreateddt = "NULL"
            if "distro" in dictScan:
              strDistro = "'{}'".format(DBClean(dictScan["distro"]))
            else:
              strDistro = "NULL"
            if "last_connect" in dictScan:
              strLastConnDT = "'{}'".format(formatUnixDate(dictScan["last_connect"]))
            else:
              strLastConnDT = "NULL"
            if "last_modification_date" in dictScan:
              strLastModDT = "'{}'".format(formatUnixDate(dictScan["last_modification_date"]))
            else:
              strLastModDT = "NULL"
            if "loaded_plugin_set" in dictScan:
              strPluginSet = "'{}'".format(DBClean(dictScan["loaded_plugin_set"]))
            else:
              strPluginSet = "NULL"
            if "platform" in dictScan:
              strPlatform = "'{}'".format(DBClean(dictScan["platform"]))
            else:
              strPlatform = "NULL"
            if "type" in dictScan:
              strPluginSet = "'{}'".format(DBClean(dictScan["type"]))
            else:
              strPluginSet = "NULL"
            if "type" in dictScan:
              strType = "'{}'".format(DBClean(dictScan["type"]))
            else:
              strType = "NULL"
            if "ui_build" in dictScan:
              strUIBuild = "'{}'".format(DBClean(dictScan["ui_build"]))
            else:
              strUIBuild = "NULL"
            if "ui_version" in dictScan:
              strUIVersion = "'{}'".format(DBClean(dictScan["ui_version"]))
            else:
              strUIVersion = "NULL"
            if "uuid" in dictScan:
              strUUID = "'{}'".format(DBClean(dictScan["uuid"]))
            else:
              strUUID = "NULL"
            if "remote_uuid" in dictScan:
              strRemoteUUID = "'{}'".format(DBClean(dictScan["remote_uuid"]))
            else:
              strRemoteUUID = "NULL"
            if "status" in dictScan:
              strStatus = "'{}'".format(DBClean(dictScan["status"]))
            else:
              strStatus = "NULL"
            if "network_name" in dictScan:
              strNetName = "'{}'".format(DBClean(dictScan["network_name"]))
            else:
              strNetName = "NULL"
            if strNetName == "'Default'":
              strNetName = "'Magenta'"
            strLocation = "'{}'".format(strLocation)
            strSQL = "select vcStatus from tblTNBLscanners where iScannerID = '{}';".format(iScannerID)
            lstReturn = SQLQuery (strSQL,dbConn)
            if not ValidReturn(lstReturn):
              LogEntry ("Unexpected: {}".format(lstReturn))
              CleanExit("due to unexpected SQL return, please check the logs")
            elif lstReturn[0] == 0:
              LogEntry ("Adding scanner {}".format(strScannerName))
              strSQL = ("INSERT INTO tblTNBLscanners (iScannerID, dtCreated,"
                " vcDistro, dtLastConnect, dtLastModified, vcPluginSet, vcName,"
                " vcPlatform, vcType, vcUIbuild, vcUIversion, vcUUID, vcRemoteUUID,"
                " vcStatus, iServerID, iAltServerID, vcAltServerSource, vcScanIP, vcIPList,"
                " vcScanType, vcLocation, vcNetName, dtLastAPIUpdate)"
                " VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {},"
                " {}, {}, {}, {}, {}, {}, {}, {}, now());".format(iScannerID, strCreateddt, strDistro, strLastConnDT,
                  strLastModDT, strPluginSet, strScannerName, strPlatform, strType, strUIBuild,
                  strUIVersion, strUUID, strRemoteUUID, strStatus, iServerID, iAltServerID, strAltSource,
                  strScanIP, strIPList, strScanType, strLocation, strNetName))
            elif lstReturn[0] == 1:
              LogEntry ("Scanner {} exists, need to update it".format(strScannerName))
              strOldStatus = lstReturn[1][0][0]
              if strOldStatus != strStatus[1:-1]:
                dictStatusChange[strScannerName[1:-1]] = strStatus[1:-1]
              if strStatus[1:-1] == "off":
                dictStatusOff[strScannerName[1:-1]] = strLastConnDT[1:-1]
              strSQL = ("UPDATE tblTNBLscanners SET dtCreated = {}, vcDistro = {},"
                " dtLastConnect = {}, dtLastModified = {}, vcPluginSet = {},"
                " vcName = {}, vcPlatform = {}, vcType = {}, vcUIbuild = {},"
                " vcUIversion = {}, vcUUID = {}, vcRemoteUUID = {}, vcStatus = {},"
                " iServerID = {}, iAltServerID = {}, vcAltServerSource = {},"
                " vcScanIP = {}, vcIPList = {}, vcScanType = {}, vcLocation = {}, vcNetName = {}, dtLastAPIUpdate = now()"
                " WHERE iScannerID = {};".format(strCreateddt, strDistro, strLastConnDT,
                  strLastModDT, strPluginSet, strScannerName, strPlatform, strType, strUIBuild,
                  strUIVersion, strUUID, strRemoteUUID, strStatus, iServerID, iAltServerID,
                  strAltSource, strScanIP, strIPList, strScanType, strLocation, strNetName, iScannerID))
            else:
              LogEntry ("Something is horrible wrong,"
                " there are {} scanners with id of {}".format(lstReturn[0],iScannerID),True)
            lstReturn = SQLQuery (strSQL,dbConn)
            if not ValidReturn(lstReturn):
              LogEntry ("Unexpected: {}".format(lstReturn))
              LogEntry (strSQL)
              CleanExit("due to unexpected SQL return, please check the logs")
            elif lstReturn[0] != 1:
              LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
            else:
              LogEntry ("{} complete".format(strScannerName))
        else:
          print("no group")
    else:
      LogEntry("Scannerlist isn't a list???? Scannerlist is a {}".format(type(dictResults["scans"])))
  else:
    LogEntry("No scanners in results, here are the first 99 character of the response: {}".format(dictResults[99:]))
  if len(lstInvalidTypes) > 0:
    SendNotification("There were {} scanners that could not be put into groups, "
      " please check logs for details.".format(len(lstInvalidTypes)))
  if len(dictStatusChange) > 0:
    strNotify = "{} Scanners changed status since last time:\n".format(len(dictStatusChange))
    for strTemp in dictStatusChange:
      strNotify += "{} New status: {}\n".format(strTemp,dictStatusChange[strTemp])
    SendNotification(strNotify)
  if len(dictStatusOff) > 0:
    strNotify = "{}  Scanners are currently in off state:\n".format(len(dictStatusOff))
    for strTemp in dictStatusOff:
      strNotify += "{} Last connected: {}\n".format(strTemp,dictStatusOff[strTemp])
    SendNotification(strNotify)

  return lstInvalidTypes

def ScanGroupDBUpdate(dictResults, dbConn):
  global dictScanGroups

  dictScanGroups = {}
  if "scanner_pools" in dictResults:
    if isinstance(dictResults["scanner_pools"],list):
      for dictScan in dictResults["scanner_pools"]:
        if "name" in dictScan:
          strGroupName = (dictScan["name"])
        else:
          strGroupName = "'Unknown Name' "
        if "id" in dictScan:
          iGroupID = (dictScan["id"])
          if not isInt(iGroupID):
            LogEntry ("Group ID is not an integer, it is '{}'. "
              " abort, abort abort.".format(iGroupID),True)
        else:
          iGroupID = "NULL"

        dictScanGroups[strGroupName] = iGroupID
        iGroupID = "{}".format(DBClean(iGroupID))
        strGroupName = "'{}'".format(DBClean(strGroupName))

        LogEntry("Group ID {} is called {}. ".format(iGroupID, strGroupName))
        strSQL = "select * from tblTNBLScanGroups where iGroupID = '{}';".format(iGroupID)
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn))
          CleanExit("due to unexpected SQL return, please check the logs")
        elif lstReturn[0] == 0:
          LogEntry ("Adding group {}".format(strGroupName))
          strSQL = ("INSERT INTO tblTNBLScanGroups (iGroupID, vcGroupName,dtLastAPIUpdate)"
            " VALUES ({}, {}, now());".format(iGroupID, strGroupName))
        elif lstReturn[0] == 1:
          LogEntry ("Scanner group {} exists, need to update it".format(strGroupName))
          strSQL = ("UPDATE tblTNBLScanGroups SET vcGroupName = {}, dtLastAPIUpdate = now()"
            " WHERE iGroupID = {};".format(strGroupName, iGroupID))
        else:
          LogEntry ("Something is horrible wrong,"
            " there are {} groups with id of {}".format(lstReturn[0],iGroupID),True)
        lstReturn = SQLQuery (strSQL,dbConn)
        if not ValidReturn(lstReturn):
          LogEntry ("Unexpected: {}".format(lstReturn))
          LogEntry (strSQL)
          CleanExit("due to unexpected SQL return, please check the logs")
        elif lstReturn[0] != 1:
          LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
        else:
          LogEntry ("{} complete".format(strGroupName))
    else:
      LogEntry("Scanner pools isn't a list???? it is a {}".format(type(dictResults["scanner_pools"])))
  else:
    LogEntry("No scanner_pools in results, here are the first 99 character of the response: {}".format(dictResults[99:]))

def Scanner2Group(dbConn):
  LogEntry("fetching all scanner members for all the defined groups")
  # strSQL = "select * from tblTNBLScanGroups;"

  for strGroupName in dictScanGroups:
    iGroupID = dictScanGroups[strGroupName]
    LogEntry ("Working on group {} {}".format(iGroupID,strGroupName))
    strSQL = "delete from tblTNBLScan2Group where iGroupID = {};".format(iGroupID)
    lstReturn = SQLQuery (strSQL,dbConn)
    if not ValidReturn(lstReturn):
      LogEntry ("Unexpected: {}".format(lstReturn))
      CleanExit("due to unexpected SQL return, please check the logs")
    else:
      LogEntry ("Deleted {} group mappings".format(lstReturn[0]))

    strAPIFunction = "scanner-groups/{}/scanners".format(iGroupID)
    strMethod = "get"

    strURL = strBaseURL + strAPIFunction
    dictResults = MakeAPICall(strURL,strHeader,strMethod)

    if "scanners" in dictResults:
      if isinstance(dictResults["scanners"],list):
        for dictScan in dictResults["scanners"]:
          if "id" in dictScan:
            iScannerID = "{}".format(DBClean(dictScan["id"]))
            if not isInt(iScannerID):
              LogEntry ("Scanner ID is not an integer, it is '{}'. "
                " abort, abort abort.".format(iScannerID),True)
          else:
            iScannerID = "NULL"
          LogEntry ("Adding {} : {}".format(iGroupID, iScannerID))
          strSQL = ("INSERT INTO tblTNBLScan2Group (iGroupID, iScannerID, dtAPIUpdate)"
            " VALUES ({}, {}, now());".format(iGroupID, iScannerID))
          lstReturn = SQLQuery (strSQL,dbConn)
          if not ValidReturn(lstReturn):
            LogEntry ("Unexpected: {}".format(lstReturn))
            LogEntry (strSQL)
            CleanExit("due to unexpected SQL return, please check the logs")
          elif lstReturn[0] != 1:
            LogEntry ("Records affected {}, expected 1 record affected".format(lstReturn[0]))
          else:
            LogEntry ("{} complete".format(iGroupID))
      else:
        LogEntry("Scanner pools isn't a list???? it is a {}".format(type(dictResults["scanners"])))
    else:
      LogEntry("No scanner_pools in results, here are the first 99 character of the response: {}".format(dictResults[99:]))

def main():
  global objLogOut
  global strScriptName
  global strScriptHost
  global tLastCall
  global iTotalSleep
  global bNotifyEnabled
  global strFormat
  global strHeader
  global strBaseURL
  global strBaseDir
  global dictConfig
  global iSlackLimit

  strFormat = "%Y-%m-%dT%H:%M:%S"
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

  strScriptName = os.path.basename(sys.argv[0])
  iLoc = strScriptName.rfind(".")
  strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
  strVersion = "{0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2])
  dictPayload = {}


  print ("This is a script to download a list of all Tenable scanners information via API. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)

  tLastCall = 0
  iTotalSleep = 0
  tStart=time.time()
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

  if "DateTimeFormat" in dictConfig:
    strFormat = dictConfig["DateTimeFormat"]
  
  if "TimeOut" in dictConfig:
    if isInt(dictConfig["TimeOut"]):
      iTimeOut = int(dictConfig["TimeOut"])
    else:
      LogEntry("Invalid timeout, setting to defaults of {}".format(iTimeOut))

  if "TextLimit" in dictConfig:
    if isInt(dictConfig["TextLimit"]):
      iSlackLimit = int(dictConfig["TextLimit"])
    else:
      LogEntry("Invalid TextLimit, setting to defaults of {}".format(iSlackLimit))

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

  if "Server" in dictConfig:
    strServer = dictConfig["Server"]
  else:
    CleanExit("No DB Server provided")

  if "dbUser" in dictConfig:
    strDBUser = dictConfig["dbUser"]
  else:
    CleanExit("No dbUser provided")

  if "dbPWD" in dictConfig:
    strDBPWD = dictConfig["dbPWD"]
  else:
    CleanExit("No dbPWD provided")

  if "InitialDB" in dictConfig:
    strInitialDB = dictConfig["InitialDB"]
  else:
    CleanExit("No InitialDB provided")

  dbConn = ""
  dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)

  strMethod = "get"

  strAPIFunction = "scanner-groups"
  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  ScanGroupDBUpdate(APIResponse,dbConn)

  strAPIFunction = "scanners"
  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  ScannerDBUpdate(APIResponse,dbConn)

  strAPIFunction = "scanner-groups"
  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  ScanGroupDBUpdate(APIResponse,dbConn)

  Scanner2Group(dbConn)

  dtNow = time.asctime()
  LogEntry ("Completed at {}".format(dtNow))
  tStop = time.time()
  iElapseSec = tStop - tStart #- iTotalSleep
  iMin, iSec = divmod(iElapseSec, 60)
  iHours, iMin = divmod(iMin, 60)
  LogEntry ("Took {0:.2f} seconds to complete, which is {1} hours, {2} minutes and {3:.2f} seconds. "
    "Of which {4} seconds was spent sleeping due to API backoff protocol.".format(iElapseSec,iHours,iMin,iSec,iTotalSleep))

  SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
  objLogOut.close()

if __name__ == '__main__':
    main()

