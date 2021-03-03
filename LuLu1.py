'''
Tenable API Script to store all current and historical scans in database
Author LuLu Pinczower Copyright 2020

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

# avoid insecure warning
requests.urllib3.disable_warnings()

# Define few things
iTimeOut = 120
iMinQuiet = 2  # Minimum time in seconds between API calls
iTotalSleep = 0
tLastCall = 0
iLineCount = 0
iTotalScan = 0


def Date2DB(strDate):
    if strDate == "":
        return 
    if strDate is None:
        return 
    strTemp = DBClean(strDate)
    strTemp = strTemp.replace("T", " ")
    return "'" + strTemp.replace("Z", "") + "'"


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
    if strText is None or strText == "None":
        return "NULL"
    elif isinstance(strText, int):
        return int(strText)
    elif isinstance(strText, float):
        return float(strText)
    else:
        strTemp = strText.encode("ascii", "ignore")
        strTemp = strTemp.decode("ascii", "ignore")
        strTemp = strTemp.replace("\\", "\\\\")
        strTemp = strTemp.replace("'", "\\'")
        try:
            strTemp = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(time.mktime(time.strptime(strTemp, strDTFormat))))
        except ValueError:
            pass
        return "\"" + strTemp + "\""


def processConf(strConf_File):
    LogEntry("Looking for configuration file: {}".format(strConf_File))
    if os.path.isfile(strConf_File):
        LogEntry("Configuration File exists")
    else:
        LogEntry("Can't find configuration file {}, make sure it is the same directory "
                 "as this script and named the same with ini extension".format(strConf_File))
        LogEntry("{} on {}: Exiting.".format(strScriptName, strScriptHost))
        objLogOut.close()
        sys.exit(9)

    strLine = "  "
    dictConfig = {}
    LogEntry("Reading in configuration")
    objINIFile = open(strConf_File, "r")
    strLines = objINIFile.readlines()
    objINIFile.close()

    for strLine in strLines:
        strLine = strLine.strip()
        iCommentLoc = strLine.find("#")
        if iCommentLoc > -1 and "dbPWD" not in strLine:
            strLine = strLine[:iCommentLoc].strip()
        else:
            strLine = strLine.strip()
        if "=" in strLine:
            strConfParts = strLine.split("=")
            strVarName = strConfParts[0].strip()
            strValue = strConfParts[1].strip()
            dictConfig[strVarName] = strValue
            if strVarName == "include":
                LogEntry("Found include directive: {}".format(strValue))
                strValue = strValue.replace("\\", "/")
                if strValue[:1] == "/" or strValue[1:3] == ":/":
                    LogEntry("include directive is absolute path, using as is")
                else:
                    strValue = strBaseDir + strValue
                    LogEntry("include directive is relative path,"
                             " appended base directory. {}".format(strValue))
                if os.path.isfile(strValue):
                    LogEntry("file is valid")
                    objINIFile = open(strValue, "r")
                    strLines += objINIFile.readlines()
                    objINIFile.close()
                else:
                    LogEntry("invalid file in include directive")


    LogEntry("Done processing configuration, moving on")
    return dictConfig


# def SendNotification(strMsg):
#     if not bNotifyEnabled:
#         return
#     global strNotifyURL
#     global strNotifyToken
#     global strNotifyChannel
#     dictNotify = {}
#     dictNotify["token"] = strNotifyToken
#     dictNotify["channel"] = strNotifyChannel
#     dictNotify["text"] = strMsg[:199]
#     strNotifyParams = urlparse.urlencode(dictNotify)
#     strURL = strNotifyURL + "?" + strNotifyParams
#     bStatus = False
#     try:
#         WebRequest = requests.get(strURL, timeout=iTimeOut)
#     except Exception as err:
#         LogEntry("Issue with sending notifications. {}".format(err))
#     if isinstance(WebRequest, requests.models.Response) == False:
#         LogEntry("response is unknown type")
#     else:
#         dictResponse = json.loads(WebRequest.text)
#         if isinstance(dictResponse, dict):
#             if "ok" in dictResponse:
#                 bStatus = dictResponse["ok"]
#                 LogEntry(
#                     "Successfully sent slack notification\n{} ".format(strMsg))
#         if not bStatus or WebRequest.status_code != 200:
#             LogEntry("Problme: Status Code:[] API Response OK={}")
#             LogEntry(WebRequest.text)


# def CleanExit(strCause):
#     SendNotification("{} is exiting abnormally on {} {}".format(
#         strScriptName, strScriptHost, strCause))
#     objLogOut.close()
#     sys.exit(9)


def LogEntry(strMsg, bAbort=False):
    strTimeStamp = time.strftime("%m-%d-%Y %H:%M:%S")
    objLogOut.write("{0} : {1}\n".format(strTimeStamp, strMsg))
    print(strMsg)
    # if bAbort:
    #     SendNotification("{} on {}: {}".format(
    #         strScriptName, strScriptHost, strMsg[:99]))
    #     CleanExit("")

# data = (iScanID, vcScheduleUuid, vcScanUuid, vcName, vcOwner, vcType, vcStatus, dtStartTime, dtEndTime, dtCreationDate, vcTimeZone, vcScannerName, iNumHosts, vcEnabled, vcRules, iPolicyID)
def LogDBEntryTblScanList(data):
    strTemp = ""
    cleanData = list(data)
    for i in range(len(data)):
        cleanData[i] = DBClean(data[i])
    cleanData = tuple(cleanData)

    strSQL = ("INSERT INTO tblScanList (iScanID, vcScheduleUuid, vcScanUuid, vcName, vcOwner, vcType, vcStatus, "
              "dtStartTime, dtEndTime, dtCreationDate, vcTimeZone, vcScannerName, iNumHosts, vcEnabled, vcRules, iPolicyID) "
              "VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}) "
              "ON DUPLICATE KEY UPDATE iScanID = {}, vcScheduleUuid = {}, vcScanUuid = {}, "
              "vcName = {}, vcOwner = {}, vcType = {}, vcStatus = {}, dtStartTime = {}, "
              "dtEndTime = {}, dtCreationDate = {}, vcTimeZone = {}, vcScannerName = {}, "
              "iNumHosts = {}, vcEnabled = {}, vcRules = {}, iPolicyID = {};".format(*cleanData, *cleanData))

    if dbConn != "":
        lstReturn = SQLQuery(strSQL, dbConn)
        if not ValidReturn(lstReturn):
            strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn, strSQL))
    else:
        strTemp = ". Database connection not established yet"

    LogEntry(strTemp)

# data = (iPolicyID, vcPolicyName, vcFamilyName, vcStatus, vcPlugins)
def LogDBEntryTblPolicyDetails(data):
    strTemp = ""
    cleanData = list(data)
    for i in range(len(data)):
        cleanData[i] = DBClean(data[i])
    cleanData = tuple(cleanData)

    strSQL = ("INSERT INTO tblPolicyDetails (iPolicyID, vcPolicyName, vcFamilyName, vcStatus, vcPlugins) "
              "VALUES ({}, {}, {}, {}, {}) "
              "ON DUPLICATE KEY UPDATE iPolicyID = {}, vcPolicyName = {}, vcFamilyName= {}, vcStatus = {}, "
              "vcPlugins = {}".format(*cleanData, *cleanData))

    if dbConn != "":
        lstReturn = SQLQuery(strSQL, dbConn)
        if not ValidReturn(lstReturn):
            strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn, strSQL))
    else:
        strTemp = ". Database connection not established yet"

    LogEntry(strTemp)

#data = (vcScheduleUuid, vcScanUuid, vcName, vcOwner, vcType, vcStatus, dtStartTime, dtEndTime)
def LogDBEntryTblScanHistory(data):
    strTemp = ""
    cleanData = list(data)
    for i in range(len(data)):
        cleanData[i] = DBClean(data[i])
    cleanData = tuple(cleanData)

    strSQL = ("INSERT INTO tblScanHistory (vcScheduleUuid, vcScanUuid, vcName, vcOwner, vcType, "
              "vcStatus, dtStartTime, dtEndTime) VALUES ({}, {}, {}, {}, {}, {}, {}, {}) "
              "ON DUPLICATE KEY UPDATE vcScheduleUuid = {}, vcScanUuid = {}, vcName = {}, vcOwner = {}, "
              "vcType = {}, vcStatus = {}, dtStartTime = {}, dtEndTime = {};".format(*cleanData, *cleanData))
              
    if dbConn != "":
        lstReturn = SQLQuery(strSQL, dbConn)
        if not ValidReturn(lstReturn):
            strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(
                lstReturn, strSQL))
        elif lstReturn[0] != 1:
            strTemp = ("   Records affected {}, expected 1 record affected when inserting log entry to the database".format(
                lstReturn[0]))
    else:
        strTemp = ". Database connection not established yet"

    LogEntry(strTemp)

# data = (vcIPAddress)
def LogDBEntryTblIPAddress(data):
    strTemp = ""
    data = "'" + data + "'"
    strSQL = ("INSERT INTO tblIPAddress (vcIPAddress) VALUES ({})"
              " ON DUPLICATE KEY UPDATE vcIPAddress = vcIPAddress;".format(data))
    if dbConn != "":
        lstReturn = SQLQuery(strSQL, dbConn)
        if not ValidReturn(lstReturn):
            strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn, strSQL))
    else:
        strTemp = ". Database connection not established yet"
    LogEntry(strTemp)

# data = (vcScheduleUuid, vcScanUuid, vcIPAddress)
def LogDBEntryTblScan2IP(data, current):
    strTemp = ""
    
    if current: 
        tableName = "tblScanList"
        tableInsert = "tblScan2IP"
    else:
        tableName = "tblScanHistory"
        tableInsert = "tblScanHistory2IP"

    iScanID = SQLQuery("SELECT iScanID FROM " + tableName + " WHERE vcScheduleUuid = '" + data[0] + "' AND vcScanUuid = '" + data[1] + "' LIMIT 1", dbConn)
    iIPID = SQLQuery("SELECT iIPID FROM tblIPAddress WHERE vcIPAddress = '" + data[2] + "' LIMIT 1", dbConn)
    
    # hacky, but scan is uniquely identified by vcScheduleUuid and vcScanUuid
    data = (str(iScanID[1]).replace('(', '').replace(')', '').replace(
        ',', ''), str(iIPID[1]).replace('(', '').replace(')', '').replace(',', ''))

    strSQL = ("INSERT INTO  " + tableInsert + "  (iScanID, iIPID) VALUES ({}, {})"
              " ON DUPLICATE KEY UPDATE iScanID = {}, iIPID = {};".format(*data, *data))

    if dbConn != "":
        lstReturn = SQLQuery(strSQL, dbConn)
        if not ValidReturn(lstReturn):
            strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(
                lstReturn, strSQL))
    else:
        strTemp = ". Database connection not established yet"

    LogEntry(strTemp)

def LogDBEntry(strTableName, strData):
    dbConn = SQLConn(strServer, strDBUser, strDBPWD, strInitialDB)
    strTemp = ""
    strData = DBClean(strData)
    strSQL = "INSERT INTO {} VALUES ({}));".format(strTableName, strData)
    if dbConn != "":
        lstReturn = SQLQuery(strSQL, dbConn)
        if not ValidReturn(lstReturn):
            strTemp = ("   Unexpected issue inserting log entry to the database: {}\n{}".format(lstReturn, strSQL))
        elif lstReturn[0] != 1:
            strTemp = ("   Records affected {}, expected 1 record affected when inserting log entry to the database".format(lstReturn[0]))
    else:
        strTemp = ". Database connection not established yet"

    strData += strTemp
    print(strTemp)


def isInt(CheckValue):
    if isinstance(CheckValue, int):
        return True
    elif isinstance(CheckValue, str):
        if CheckValue.isnumeric():
            return True
        else:
            return False
    else:
        return False


def ConvertFloat(fValue):
    if isinstance(fValue, (float, int, str)):
        try:
            fTemp = float(fValue)
        except ValueError:
            fTemp = "NULL"
    else:
        fTemp = "NULL"
    return fTemp


def MakeAPICall(strURL, strHeader, strMethod,  dictPayload=""):
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
                WebRequest = requests.post(
                    strURL, json=dictPayload, headers=strHeader, verify=False)
            else:
                WebRequest = requests.post(
                    strURL, headers=strHeader, verify=False)
            # LogEntry ("post executed")
        if strMethod.lower() == "put":
            if dictPayload != "":
                WebRequest = requests.put(
                    strURL, json=dictPayload, headers=strHeader, verify=False)
            else:
                WebRequest = requests.put(
                    strURL, headers=strHeader, verify=False)
            # LogEntry ("post executed")
    except Exception as err:
        LogEntry("Issue with API call. {}".format(err))
        # CleanExit("due to issue with API, please check the logs")

    if WebRequest is None:
        LogEntry("response is none type", True)
        iErrCode = "NoneType"
        iErrText = "response is none type"

    if isinstance(WebRequest, requests.models.Response) == False:
        LogEntry("response is unknown type")
        iErrCode = "ResponseErr"
        iErrText = "response is unknown type"

    # LogEntry ("call resulted in status code {}".format(WebRequest.status_code))
    if WebRequest.status_code != 200:
        LogEntry(WebRequest.text)
        iErrCode = WebRequest.status_code
        iErrText = WebRequest.text
        print("Tenable Error")

    if iErrCode != "" or WebRequest.status_code != 200:
        return "There was a problem with your request. HTTP error {} code {} {}".format(WebRequest.status_code, iErrCode, iErrText)
    else:
        try:
            return WebRequest.json()
        except Exception as err:
            LogEntry("Issue with converting response to json. Here are the first 99 character of the response: {}".format(
                WebRequest.text[:99]))


def CleanStr(strOld):
    strTemp = strOld.replace('"', '')
    strTemp = strTemp.replace(',', '')
    strTemp = strTemp.replace('\n', '')
    return strTemp.strip()


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
    global strOutPath
    global strServer
    global strDBUser
    global strDBPWD
    global strInitialDB
    global strDTFormat
    global dbConn

    strNotifyToken = None
    strNotifyChannel = None
    strNotifyURL = None
    ISO = time.strftime("-%Y-%m-%d-%H-%M-%S")
    tStart = time.time()

    strBaseDir = os.path.dirname(sys.argv[0])
    strRealPath = os.path.realpath(sys.argv[0])
    strRealPath = strRealPath.replace("\\", "/")
    if strBaseDir == "":
        iLoc = strRealPath.rfind("/")
        strBaseDir = strRealPath[:iLoc]
    if strBaseDir[-1:] != "/":
        strBaseDir += "/"
    strLogDir = strBaseDir + "Logs/"
    if strLogDir[-1:] != "/":
        strLogDir += "/"

    iLoc = sys.argv[0].rfind(".")
    strConf_File = sys.argv[0][:iLoc] + ".ini"

    if not os.path.exists(strLogDir):
        os.makedirs(strLogDir)
        print(
            "\nPath '{0}' for log files didn't exists, so I create it!\n".format(strLogDir))

    strScriptName = os.path.basename(sys.argv[0])
    iLoc = strScriptName.rfind(".")
    strLogFile = strLogDir + strScriptName[:iLoc] + ISO + ".log"
    strVersion = "{0}.{1}.{2}".format(
        sys.version_info[0], sys.version_info[1], sys.version_info[2])
    strScriptHost = platform.node().upper()

    print("This is a script to pull all Target Groups and Tags via API and generate CSV files. This is running under Python Version {}".format(strVersion))
    print("Running from: {}".format(strRealPath))
    dtNow = time.asctime()
    print("The time now is {}".format(dtNow))
    print("Logs saved to {}".format(strLogFile))
    objLogOut = open(strLogFile, "w", 1)

    dictConfig = processConf(strConf_File)
    strHeader = {}
    if "AccessKey" in dictConfig and "Secret" in dictConfig:
        strHeader = {
            'Content-type': 'application/json',
            'X-ApiKeys': 'accessKey=' + dictConfig["AccessKey"] + ';secretKey=' + dictConfig["Secret"]}
    else:
        LogEntry("API Keys not provided, exiting.", True)

    # if "NotifyToken" in dictConfig and "NotifyChannel" in dictConfig and "NotificationURL" in dictConfig:
    #     bNotifyEnabled = True
    # else:
    #     bNotifyEnabled = False
    #     LogEntry("Missing configuration items for Slack notifications, "
    #              "turning slack notifications off")

    if "APIBaseURL" in dictConfig:
        strBaseURL = dictConfig["APIBaseURL"]
    # else:
        # CleanExit("No Base API provided")
    if strBaseURL[-1:] != "/":
        strBaseURL += "/"

    # if "NotifyEnabled" in dictConfig:
    #     if dictConfig["NotifyEnabled"].lower() == "yes" \
    #             or dictConfig["NotifyEnabled"].lower() == "true":
    #         bNotifyEnabled = True
    #     else:
    #         bNotifyEnabled = False

    if "DateTimeFormat" in dictConfig:
        strDTFormat = dictConfig["DateTimeFormat"]

    if "TimeOut" in dictConfig:
        if isInt(dictConfig["TimeOut"]):
            iTimeOut = int(dictConfig["TimeOut"])
        else:
            LogEntry("Invalid timeout, setting to defaults of {}".format(iTimeOut))

    if "MinQuiet" in dictConfig:
        if isInt(dictConfig["MinQuiet"]):
            iMinQuiet = int(dictConfig["MinQuiet"])
        else:
            LogEntry(
                "Invalid MinQuiet, setting to defaults of {}".format(iMinQuiet))

    if "OutPath" in dictConfig:
        strOutPath = dictConfig["OutPath"]
    else:
        strOutPath = strBaseDir

    strOutPath = strOutPath.replace("\\", "/")

    if strOutPath[-1:] != "/":
        strOutPath += "/"

    if "Server" in dictConfig:
        strServer = dictConfig["Server"]

    if "dbUser" in dictConfig:
        strDBUser = dictConfig["dbUser"]

    if "dbPWD" in dictConfig:
        strDBPWD = dictConfig["dbPWD"]

    if "InitialDB" in dictConfig:
        strInitialDB = dictConfig["InitialDB"]

    print("server: " + strServer)
    print("initial DB: " + strInitialDB)
    dbConn = SQLConn(strServer, strDBUser, strDBPWD, strInitialDB)
    # clear and restart increment for tables using auto-incrementation
    # for table in ["tblScanHistory", "tblScan2IP", "tblScanHistory2IP", "tblPolicyDetails"]:
    #     SQLQuery("DELETE FROM " + table, dbConn)
    #     SQLQuery("ALTER TABLE " + table + " AUTO_INCREMENT = 1", dbConn)

####################################### call to get recent scans ############################################################
    scheduleUuidFKs = []
    dictPayload = {}
    strMethod = "get"
    strAPIFunctionRecent = "scans/"
    strURLRecent = strBaseURL + strAPIFunctionRecent
    LogEntry("Pulling a list of all recent scans")
    APIResponseRecent = MakeAPICall(
        strURLRecent, strHeader, strMethod, dictPayload)
    
    if "scans" in APIResponseRecent:
        if isinstance(APIResponseRecent["scans"], list):
            for recentDict in APIResponseRecent["scans"]:
                iScanID = recentDict["id"]
                vcScanUuid = recentDict["uuid"]
                if vcScanUuid is not None:
                    vcScheduleUuid = recentDict["schedule_uuid"]
                    scheduleUuidFKs.append(vcScheduleUuid)

                    # from API call to Scan list
                    strAPIFunctionDetails = "scans/" + str(vcScheduleUuid) + "/"
                    strURLDetails = strBaseURL + strAPIFunctionDetails
                    APIResponseDetails = MakeAPICall(strURLDetails, strHeader, strMethod, dictPayload)

                    vcName = recentDict["name"]
                    dtCreationDate = formatUnixDate(recentDict["creation_date"])
                    vcStatus = recentDict["status"]
                    vcOwner = recentDict["owner"]
                    vcType = recentDict["type"]
                    vcTimeZone = recentDict["timezone"]
                    vcEnabled = recentDict["enabled"]
                    vcRules = recentDict["rrules"]
                    iPolicyID = recentDict["policy_id"]

                    # from API call to Policy Details
                    if iPolicyID is not None:
                        strAPIFunctionPolicy = "policies/" + str(iPolicyID) + "/"
                        strURLPolicy = strBaseURL + strAPIFunctionPolicy
                        APIResponsePolicy = MakeAPICall(strURLPolicy, strHeader, strMethod, dictPayload)
                        if isinstance(APIResponsePolicy, dict):
                            vcPolicyName = APIResponsePolicy["settings"]["name"]
                            if "plugins" in APIResponsePolicy:
                                families = APIResponsePolicy["plugins"]
                                for family in families:
                                    vcFamilyName = family
                                    family = families[family]
                                    vcStatus = family["status"]
                                    plugins = []
                                    if "individual" in family:    
                                        for plugin in family["individual"]:
                                            plugins.append(plugin)
                                    numPlugins = len(plugins)
                                    vcPlugins = ""
                                    if numPlugins > 0:
                                        vcPlugins += plugins[0]
                                        for i in range(numPlugins - 2):
                                            vcPlugins += ", " + plugins[i + 1]
                                data = (iPolicyID, vcPolicyName, vcFamilyName, vcStatus, vcPlugins)
                                LogDBEntryTblPolicyDetails(data)

                    # from API call to Scan Details
                    if "info" in APIResponseDetails:
                        recentDetailDict = APIResponseDetails["info"]
                        vcScannerName = recentDetailDict["scanner_name"]
                        vcStatus = recentDetailDict["status"]
                        iNumHosts = recentDetailDict.get("hostcount")
                        # iNumHosts = 0 if targets == None else targets.count(",") + 1
                        dtStartTime = formatUnixDate(recentDetailDict["scan_start"])
                        dtEndTime = formatUnixDate(recentDetailDict.get("scan_end"))

                    data = (iScanID, vcScheduleUuid, vcScanUuid, vcName, vcOwner, vcType, vcStatus, dtStartTime, dtEndTime, dtCreationDate, vcTimeZone, vcScannerName, iNumHosts, vcEnabled, vcRules, iPolicyID)
                    LogDBEntryTblScanList(data)
                    LogAlltargets(recentDetailDict, vcScheduleUuid, vcScanUuid, True)

                    if not isinstance(APIResponseDetails, list) and not isinstance(APIResponseDetails, dict):
                        LogEntry("Error in retrieving history of scan")
                        LogEntry(APIResponseDetails)
                    else:
                        # from API call to Scan History Details
                        history = APIResponseDetails["history"]
                        # historyUuidFKs = []
                        for historicalScan in history:
                            vcHScanUuid = historicalScan["uuid"]
                            strAPIFunctionHistory = "scans/" + \
                                str(vcScheduleUuid) + "/history/" + \
                                str(vcScanUuid)
                            strURLHistory = strBaseURL + strAPIFunctionHistory
                            APIResponseHistory = MakeAPICall(
                                strURLHistory, strHeader, strMethod, dictPayload)

                            vcName = APIResponseHistory["name"]
                            vcOwner = APIResponseHistory["owner"]
                            vcType = APIResponseHistory["scan_type"]
                            vcStatus = APIResponseHistory["status"]
                            dtStartTime = formatUnixDate(APIResponseHistory["scan_start"])
                            dtEndTime = formatUnixDate(APIResponseHistory["scan_end"])

                            data = (vcScheduleUuid, vcHScanUuid, vcName, vcOwner, vcType, vcStatus, dtStartTime, dtEndTime)
                            LogDBEntryTblScanHistory(data)
                            LogAlltargets(APIResponseHistory, vcScheduleUuid, vcScanUuid, False)

        else:
            LogEntry("Values is not a list, no idea what to do with this: {}".format(
                APIResponseRecent), True)
    else:
        LogEntry("Unexpected results: {}".format(APIResponseRecent), True)

    LogEntry("Done!")

# log each individual IPAddress in list of targets
def LogAlltargets(dictionary, scheduleUuid, vcScanUuid, current):
    if "targets" in dictionary:
        targets = dictionary["targets"]
        if targets is not None:
            # hacky, some are split by "," and some "\n"
            targetsSplitComma = targets.split(",")
            targetsSplitNewLine = targets.split("\n")
            if len(targetsSplitComma) > len(targetsSplitNewLine):
                targets = targetsSplitComma
            else:
                targets = targetsSplitNewLine
            for IPAddress in targets:
                LogDBEntryTblIPAddress((IPAddress.strip()))
                LogDBEntryTblScan2IP((scheduleUuid, vcScanUuid, IPAddress), current)

def QDate2DB(strDate):
    strTemp = strDate.replace("T", " ")
    return str(strTemp.replace("Z", ""))


def FormatTenableDate(strdate):
    if strdate == "Invalid Date":
        return
    if strdate is None or strdate == "Invalid date":
        return 
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
    if iDate == "Invalid date":
        return 
    else:
        structTime = time.localtime(iDate)
        return time.strftime(strDTFormat, structTime)


if __name__ == '__main__':
    main()
