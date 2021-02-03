'''
Tenable API Script to add nessus agents to the correct group.
Author Siggi Bjarnason Copyright 2021
Website https://supergeek.us

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

#Define few things
iTotalSleep = 0
tLastCall = 0
iTotalAdded = 0

#avoid insecure warning
requests.urllib3.disable_warnings()

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
  SendNotification("{} is exiting abnormally on {} {}".format(strScriptName,strScriptHost, strCause))
  objLogOut.close()
  print ("objLogOut closed")
  if dbConn != "":
    dbConn.close()
  print ("dbConn closed")

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
    strFullLine = strLine.strip()
    iCommentLoc = strLine.find("#")
    if iCommentLoc > -1:
      strLine = strLine[:iCommentLoc].strip()
    else:
      strLine = strLine.strip()
    if "=" in strLine:
      strConfParts = strLine.split("=")
      strVarName = strConfParts[0].strip()
      strValue = strConfParts[1].strip()
      if "password" in strVarName.lower() or "pwd" in strVarName.lower():
        LogEntry("Varname is {}, assigning full value".format(strVarName))
        iLoc = strFullLine.find("=")
        dictConfig[strVarName] = strFullLine[iLoc+1:].strip()
      else:
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

def MakeAPICall (strURL, dictHeader, strMethod, dictPayload="",strUser="",strPWD=""):

  global tLastCall
  global iTotalSleep

  iTimeOut = 120
  strUserName = strUser
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

  LogEntry ("Doing a {} to URL: \n {}".format(strMethod,strURL))
  # print ("UID:{} PWD:{}".format(strUser, strPWD))
  try:
    if strMethod.lower() == "get":
      if strUser != "" and strPWD != "":
        LogEntry("I have none blank credentials so I'm doing basic auth")
        # WebRequest = requests.get(strURL, headers=dictHeader, auth=(strUser, strPWD))
        WebRequest = requests.get(strURL,timeout=iTimeOut, headers=dictHeader, auth=(strUserName, strPWD))
      else:
        LogEntry("credentials are blank, proceeding without auth")
        WebRequest = requests.get(strURL, headers=dictHeader, verify=False)
      LogEntry ("get executed")
    elif strMethod.lower() == "put":
      WebRequest = requests.put(strURL, headers=dictHeader, verify=False)
      LogEntry ("put executed")
    elif strMethod.lower() == "post":
      if dictPayload != "":
        WebRequest = requests.post(strURL, json= dictPayload, headers=dictHeader, verify=False)
      else:
        WebRequest = requests.post(strURL, headers=dictHeader, verify=False)
      LogEntry ("post executed")
    else:
      LogEntry ("unknown method: {}".format(strMethod),True)
  except Exception as err:
    LogEntry ("Issue with API call. {}".format(err))
    # CleanExit ("due to issue with API, please check the logs")
    return "API Error"

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
    if WebRequest.text == "":
      return None
    try:
      return WebRequest.json()
    except Exception as err:
      LogEntry ("Issue with converting response to json. Here are the first 99 character of the response: '{}'".format(WebRequest.text[:99]))

def GetGroupID(strGroupName):
  dictPayload = {}
  iGroupID = -56
  LogEntry("Getting group ID")
  strMethod = "get"
  strAPIFunction = "scanners/scanner_id/agent-groups"
  strURL = strBaseURL + strAPIFunction
  APIResponse = MakeAPICall(strURL,dictHeader,strMethod, dictPayload)
  if isinstance(APIResponse,dict):
    if "groups" in APIResponse:
      if isinstance(APIResponse["groups"],list):
        for dictGroups in APIResponse["groups"]:
          if dictGroups["name"]==strGroupName:
            iGroupID = dictGroups["id"]
            LogEntry("Group {} already exists with ID of {}".format(strGroupName, iGroupID))
      else:
        LogEntry("Groups list isn't a list???? Groups list is a {}".format(type(APIResponse["groups"])))
    else:
      LogEntry("No Groups in results, here are the first 99 character of the response: {}".format(APIResponse[99:]))
  else:
    LogEntry("Result is not a dictionary, here are the first 99 character of the response: {}".format(APIResponse[99:]))

  if iGroupID == -56:
    strMethod = "post"
    dictPayload["name"]=strGroupName
    strURL = strBaseURL + strAPIFunction
    APIResponse = MakeAPICall(strURL,dictHeader,strMethod, dictPayload)
    if "id" in APIResponse:
      iGroupID = APIResponse["id"]
      LogEntry("Group {} did not exists, was created with ID {}".format(strGroupName, iGroupID))
    else:
      LogEntry("No ID returned after creating a group, bailing",True)
  return iGroupID

def Add2Group(strGroupName,dictAgents):
  global dictGroupIDs
  global iTotalAdded

  bAdd2Group = True
  dictPayload = {}
  GroupAddResponse = None

  if "groups" in dictAgents:
    for dictAgentGroup in dictAgents["groups"]:
      if dictAgentGroup["name"][:3] == "ECS" :
        LogEntry("ECS asset")
        bAdd2Group = False
        break
      if dictAgentGroup["name"] == strGroupName:
        LogEntry("already in the right group")
        bAdd2Group = False
        break
      else:
        bAdd2Group = True
  else:
    bAdd2Group = True
    LogEntry ("not in any groups sofar")

  if bAdd2Group:
    LogEntry("Adding {} to '{}'".format(dictAgents["name"],strGroupName))
    if strGroupName in dictGroupIDs:
      iGroupID = dictGroupIDs[strGroupName]
    else:
      iGroupID = GetGroupID(strGroupName)
      dictGroupIDs[strGroupName] = iGroupID
      print ("Group ID is {}".format(iGroupID))
    strAPIFunction = "scanners/scanner_id/agent-groups/"+str(iGroupID)+"/agents/"+str(dictAgents["id"])
    strMethod = "put"
    strURL = strBaseURL + strAPIFunction
    LogEntry("Adding {} to group {}.".format(dictAgents["name"],strGroupName))
    GroupAddResponse = MakeAPICall(strURL,dictHeader,strMethod, dictPayload)
    LogEntry("Added {} to group {}. The response is: {}".format(
        dictAgents["name"],strGroupName,GroupAddResponse))
    iTotalAdded += 1

  return GroupAddResponse

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

def CalcNet(strIPAddr):
  if strIPAddr.count(".")<3 or strIPAddr.count(".")>3:
    strNetType = "invalidNet"
  else:
    strIPparts = strIPAddr.split(".")
    # print ("IP address is {}, first part is {} and second part is {}".format(strIPAddr,strIPparts[0],strIPparts[1]))
    if int(strIPparts[0]) == 10 and int(strIPparts[1]) < 160:
      strNetType = "EIT"
    elif int(strIPparts[0]) == 10 and int(strIPparts[1]) < 240:
      strNetType = "CoreNet"
    elif int(strIPparts[0]) == 10:
      strNetType = "NMnet"
    elif int(strIPparts[0]) == 5:
      strNetType = "NMnet"
    else:
      strNetType = "UnknownNet"
  # print (strNetType)
  return strNetType

def InspectSNValue(CheckValue):
  if isinstance(CheckValue,dict):
    if "display_value" in CheckValue:
      return CheckValue["display_value"]
    elif "value" in CheckValue:
      return CheckValue["value"]
    else:
      return "Unknown dict"
  elif isinstance(CheckValue,str):
    return CheckValue
  elif CheckValue is None:
    return ""
  else:
    return type(CheckValue)

def QuerySNServers(strPlatform,strServerName):

  dictHeader = {}
  dictPayload = {}
  dictResults = {}
  strLocCode = "unknown"
  strMethod = "get"
  dictHeader["Content-Type"] = "application/json"
  dictHeader["Accept"] = "application/json"

  if strPlatform == "LINUX":
    strAPIFunction = "api/now/table/cmdb_ci_linux_server?"
  elif strPlatform == "WINDOWS":
    strAPIFunction = "api/now/table/cmdb_ci_win_server?"
  else:
    LogEntry("neither linux nor Windows, can't deal with that!")
    return dictResults

  strParam = ("sysparm_display_value=true&sysparm_query=name=")
  strURL = strSNBaseURL + strAPIFunction + strParam + strServerName
  LogEntry("fetching server from ServiceNow")
  APIResponse = MakeAPICall(strURL,dictHeader,strMethod,dictPayload,strSNUser,strSNPWD)

  if isinstance(APIResponse,dict):
    if "result" in APIResponse:
      if "error_message" in APIResponse["result"]:
        LogEntry ("Error Occured: {}".format(APIResponse["result"]["error_message"]),True)
      elif isinstance(APIResponse["result"],list):
        if len(APIResponse["result"]) > 0:
          LogEntry ("There are {} items in the results. Only processing item 1".format(len(APIResponse["result"])))
          dictItem = APIResponse["result"][0]
          if "used_for" in dictItem:
            dictResults["used_for"] = InspectSNValue (dictItem["used_for"])
            LogEntry("Used for: {}".format(dictResults["used_for"]))
          if "location" in dictItem:
            dictResults["location"] = InspectSNValue (dictItem["location"])
            LogEntry("Location: {}".format(dictResults["location"]))
        else:
          LogEntry("Result list is empty")
      else:
        LogEntry ("no list. result is type: {}".format(type(APIResponse["result"])))
    else:
      LogEntry ("no results:\n{}".format(APIResponse))
  elif isinstance(APIResponse,str):
    LogEntry (APIResponse)
    dictResults = APIResponse
  else:
    LogEntry("Response is neither dict nor a string. It is a {} and here is the content:{}".format(type(APIResponse),APIResponse))
    dictResults = APIResponse


  if isinstance(dictResults,dict):
    if "location" in dictResults:
      strSQL = "select vcSiteCode from tblSiteCodes where vcSNLocation = '{}';".format(dictResults["location"])
      lstReturn = SQLQuery (strSQL,dbConn)
      if not ValidReturn(lstReturn):
        LogEntry ("Unexpected: {}".format(lstReturn))
        CleanExit("due to unexpected SQL return, please check the logs")
      elif lstReturn[0] == 0:
        strLocCode = "unknown"
        LogEntry ("location {} not in location table".format(dictResults["location"]))
      elif lstReturn[0] > 1:
        SendNotification ("More than one instance of {} in location table,"
          " picking the first one".format(dictResults["location"]))
        LogEntry ("More than one instance of {} in location table,"
          " picking the first one".format(dictResults["location"]))
        strLocCode = (lstReturn[1][0][0])
      else:
        strLocCode = (lstReturn[1][0][0])

    if "used_for" in dictResults:
      if dictResults["used_for"] == "Testing" and strLocCode != "unknown":
        strLocCode = "NPE-{}".format(strLocCode)
      else:
        strLocCode = "{}".format(strLocCode)
    else:
      if strServerName[1:3].lower() == "prd":
        dictResults["used_for"] = "Production"
      if strServerName[1:3].lower() == "tst":
        dictResults["used_for"] = "Testing"


  if strLocCode == "unknown":
    if strServerName[1:6].lower() == "prdpl":
      strLocCode = "POL"
    if strServerName[1:6].lower() == "prdtl":
      strLocCode = "TTN"
    if strServerName[1:6].lower() == "tstpl":
      strLocCode = "NPE-POL"
    if strServerName[1:6].lower() == "tsttl":
      strLocCode = "NPE-TTN"
  LogEntry("LocCode:{}".format(strLocCode))
  dictResults["LocCode"] = strLocCode

  return(dictResults)

def main():
  global objLogOut
  global strScriptName
  global strScriptHost
  global tLastCall
  global iTotalSleep
  global strBaseURL
  global dictConfig
  global strFormat
  global bNotifyEnabled
  global iMinQuiet
  global iTimeOut
  global strBaseDir
  global iLimit
  global dictHeader
  global dictGroupIDs
  global iTotalAdded
  global strSNUser
  global strSNPWD
  global strSNBaseURL
  global dbConn

  #Define few things
  iTimeOut = 120
  iMinQuiet = 2 # Minimum time in seconds between API calls
  ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
  dictParams = {}
  dictParams["limit"] = "5000"
  # dictParams["mode"] = "full"
  # dictParams["mode"] = "extended"
  iLimit = 5000
  bNotifyEnabled = False
  dbConn = ""

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
  dictPayload = {}
  strScriptHost = platform.node().upper()

  print ("This is a script to download Tenable Agent list via API. This is running under Python Version {}".format(strVersion))
  print ("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print ("The time now is {}".format(dtNow))
  print ("Logs saved to {}".format(strLogFile))
  objLogOut = open(strLogFile,"w",1)

  tLastCall = 0
  iTotalSleep = 0
  tStart=time.time()
  dictConfig = processConf(strConf_File)
  if "AccessKey" in dictConfig and "Secret" in dictConfig:
    dictHeader={
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

  if "Limit" in dictConfig:
    if isInt(dictConfig["Limit"]):
      iLimit = int(dictConfig["Limit"])
    else:
      LogEntry("Invalid limit, setting to defaults of {}".format(iLimit))
  else:
    LogEntry("No limit provided, setting to defaults of {}".format(iLimit))

  if "SNAPIBaseURL" in dictConfig:
    strSNBaseURL = dictConfig["SNAPIBaseURL"]
  else:
    CleanExit("No SNOW Base API provided")

  if strSNBaseURL[-1:] != "/":
    strSNBaseURL += "/"

  if "SNUserID" in dictConfig:
    strSNUser = dictConfig["SNUserID"]
  else:
    LogEntry("No SNOW UserID")

  if "SNUserPWD" in dictConfig:
    strSNPWD = dictConfig["SNUserPWD"]
  else:
    LogEntry("No SNOW PWD")

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


  dictResults = {}
  dictGroupIDs = {}

  iOffset = 0
  iTotalAgents = iLimit
  dictParams["limit"] = iLimit
  iTotalProcessed = 0
  

  dbConn = SQLConn (strServer,strDBUser,strDBPWD,strInitialDB)

  while iTotalProcessed < iTotalAgents:
    strAPIFunction = "scanners/scanner_id/agents"
    strMethod = "get"
    dictParams["offset"] = iOffset
    if isinstance(dictParams,dict) and len(dictParams) > 0:
      strListScans = urlparse.urlencode(dictParams)
      strURL = strBaseURL + strAPIFunction +"?" + strListScans
    else:
      strURL = strBaseURL + strAPIFunction
    APIResponse = MakeAPICall(strURL,dictHeader,strMethod, dictPayload)
    if isinstance(APIResponse,dict):
      if "agents" in APIResponse:
        if isinstance(APIResponse["agents"],list):
          for dictAgents in APIResponse["agents"]:
            LogEntry ("processing platform specific groups")
            LogEntry ("platform for {} is {}".format(dictAgents["name"],dictAgents["platform"]))
            strOS = dictAgents["platform"]
            GroupAddResponse = Add2Group(strOS,dictAgents)
            LogEntry ("processing IP specific groups")
            strNetType = CalcNet(dictAgents["ip"])
            if strNetType == "UnknownNet":
              LogEntry("Unknown Net type for IP address {}".format(dictAgents["ip"]))
            if strNetType == "invalidNet":
              LogEntry("IP address {} is not a valid IPv4 address")
            LogEntry ("Net type for {} is {}".format(dictAgents["name"],strNetType))
            GroupAddResponse = Add2Group(strNetType,dictAgents)
            if "groups" in dictAgents:
              if isinstance(dictAgents["groups"],list):
                if len(dictAgents["groups"]) > 3:
                  LogEntry("Agent is in more than three groups, skipping to next one.")
                  continue
            LogEntry ("Now querying SNOW for details on {}".format(dictAgents["name"]))
            dictResults = QuerySNServers(dictAgents["platform"],dictAgents["name"])
            strLocCode = "unknown location"
            strUseCode = "unknown use"
            if isinstance(dictResults,dict):
              LogEntry("Adding used for group")
              if "used_for" in dictResults:
                if dictResults["used_for"].strip() != "":
                  strUseCode = dictResults["used_for"]
              GroupAddResponse = Add2Group(strUseCode,dictAgents)
              LogEntry("Adding location group")
              if "LocCode" in dictResults:
                if dictResults["LocCode"].strip() != "":
                  strLocCode = dictResults["LocCode"]
              GroupAddResponse = Add2Group(strLocCode,dictAgents)
              if strLocCode != "unknown location" and strUseCode != "unknown use" :
                GroupAddResponse = Add2Group(strLocCode+"-"+strUseCode,dictAgents)
                GroupAddResponse = Add2Group(strLocCode+"-"+strUseCode+"-"+strOS,dictAgents)
              if strUseCode != "unknown use" :
                GroupAddResponse = Add2Group(strUseCode+"-"+strOS,dictAgents)
            else:
              LogEntry("Result is not a dict it is type:{}".format(type(dictResults)),True)
            iTotalProcessed += 1
            LogEntry(GroupAddResponse)
            if iOffset == 0:
              iTotalAgents = "n/a"
            LogEntry ("Processed: {}, added:{}, total: {}, offset:{}, limit:{}".format(iTotalProcessed,iTotalAdded,
                      iTotalAgents,iOffset,iLimit))
        else:
          LogEntry("Agent list isn't a list???? Agent list is a {}".format(type(APIResponse["agents"])))
      else:
        LogEntry("No Agents in results, here are the first 99 character of the response: {}".format(APIResponse[99:]))
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
      LogEntry ("Processed: {}, total: {}, offset:{}, limit:{}".format(iTotalProcessed,iTotalAgents,iROffset,iRLimit))
      iOffset += iLimit
    else:
      CleanExit("APIResponse not a dict, it is {}".format(type(APIResponse)))

  LogEntry ("Completed {} rows at {}. Added {} agents to groups".format(iTotalProcessed,dtNow,iTotalAdded))
  tStop = time.time()
  iElapseSec = tStop - tStart - iTotalSleep
  iMin, iSec = divmod(iElapseSec, 60)
  iHours, iMin = divmod(iMin, 60)
  dtNow = time.asctime()
  LogEntry ("Took {0:.2f} seconds to complete, which is {1} hours, {2} minutes and {3:.2f} seconds.".format(
              iElapseSec,iHours,iMin,iSec))

  SendNotification ("{} completed successfully on {}".format(strScriptName, strScriptHost))
  objLogOut.close()
  dbConn.close()

if __name__ == '__main__':
    main()