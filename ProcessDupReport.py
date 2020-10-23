'''
Tenable API Script to capture details of certain tenable assets. Reads a json file provided
by Tenable support and generates another json with more details
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
iTimeOut = 120
iMinQuiet = 2 # Minimum time in seconds between API calls
iTotalSleep = 0
tLastCall = 0
iTotalScan = 0
dictPayload = {}
strMethod = "get"

def formatUnixDate(iDate):
  if iDate > 9999999999:
    iDate = iDate / 1000
  structTime = time.localtime(iDate)
  return time.strftime(strFormat,structTime)

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
  objJSON.close()
  objOutFile.close()  
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

def CleanStr(strOld):
  strTemp = strOld.replace('"','')
  strTemp = strTemp.replace(',','')
  strTemp = strTemp.replace('\n','')
  return strTemp.strip()

def ProcessAPI(strURL):
  APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
  if not isinstance(APIResponse, dict):
    LogEntry ("Expecting a dictionary, got: {}".format(APIResponse))
    LogEntry ("Waiting two minutes then trying the call again")
    time.sleep(120)
    APIResponse = MakeAPICall(strURL,strHeader,strMethod, dictPayload)
    if not isinstance(APIResponse, dict):
      LogEntry("Got unexpected result second time around, giving up. Response was {}".format(APIResponse),True)
  if "id" in APIResponse:
    strUUID=APIResponse["id"]
  else:
    LogEntry("No id entry")
    strUUID=""
  if "has_agent" in APIResponse:
    bHasAgent=APIResponse["has_agent"]
  else:
    LogEntry("No has_agent entry")
    bHasAgent=""
  if "last_seen" in APIResponse:
    dtLastSeen=APIResponse["last_seen"]
  else:
    LogEntry("No last_seen entry")
    dtLastSeen=""
  if "last_authenticated_scan_date" in APIResponse:
    dtLastAuth=APIResponse["last_authenticated_scan_date"]
  else:
    LogEntry("No last_authenticated_scan_date entry")
    dtLastAuth=""
  if "last_licensed_scan_date" in APIResponse:
    dtLastLicense=APIResponse["last_licensed_scan_date"]
  else:
    LogEntry("No last_licensed_scan_date entry")
    dtLastLicense=""
  if "ipv4" in APIResponse:
    strIPv4="|".join(APIResponse["ipv4"])
  else:
    LogEntry("No ipv4 entry")
    strIPv4=""
  if "fqdn" in APIResponse:
    strFQDN="|".join(APIResponse["fqdn"])
  else:
    LogEntry("No fqdn entry")
    strFQDN=""
  if "netbios_name" in APIResponse:
    strNetBIOSName="|".join(APIResponse["netbios_name"])
  else:
    LogEntry("No netbios_name entry")
    strNetBIOSName=""
  if "operating_system" in APIResponse:
    strOS="|".join(APIResponse["operating_system"])
  else:
    LogEntry("No operating_system entry")
    strOS=""
  if "system_type" in APIResponse:
    strSysType="|".join(APIResponse["system_type"])
  else:
    LogEntry("No system_type entry")
    strSysType=""
  if "mac_address" in APIResponse:
    strMACAddrCount="Found {} MAC Addresses".format(len(APIResponse["mac_address"]))
  else:
    LogEntry("No mac_address entry")
    strMACAddrCount=""
  return ("{},{},{},{},{},{},{},{},{},{},{}".format(strUUID,strFQDN,strNetBIOSName,
    strIPv4,bHasAgent,strMACAddrCount,strSysType,strOS,dtLastSeen,dtLastAuth,dtLastLicense))  

def main():
  global ISO
  global bNotifyEnabled
  global iMinQuiet
  global iTimeOut
  global iTotalSleep
  global objLogOut
  global objJSON
  global objOutFile
  global strBaseDir
  global strNotifyChannel
  global strNotifyToken
  global strNotifyURL
  global strScriptHost
  global strScriptName
  global tLastCall
  global tStart
  global strFormat
  global strHeader

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

  print ("This is a script to provide more details about specific Tenable assetIDs. This is running under Python Version {}".format(strVersion))
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
  
  if "Infile" in dictConfig:
    strInFile = dictConfig["Infile"]
  else:
    LogEntry("No Infile provided, unable to proceed",True)

  if "OutFile" in dictConfig:
    strOutFile = dictConfig["OutFile"]
  else:
    LogEntry("No OutFile provided, unable to proceed",True)

  strOutFile = strOutFile.replace("\\","/")

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

  if os.path.isfile(strInFile):
    LogEntry ("Provided infile does exists")
  else:
    LogEntry ("Can't find specified input file {}, "
      " unable to proceed without a valid infile".format(strInFile),True)
  objJSON=open(strInFile,"r")
  lstJSON=json.load(objJSON)
  iJSONLen=len(lstJSON)
  iLineCount = 0

  strCSVHead = "UUID,FQDN,NetBIOS Name,IPv4,HasAgent,MAC Addr Count,SysType,OS,Last Seen,Last Auth Scan,Last Licensed Scan"
  objOutFile = open(strOutFile,"w",1)
  objOutFile.write(strCSVHead)
  strAPIFunction = "assets/"

  for dictJSON in lstJSON:
    iLineCount += 1
    strAssetID = dictJSON['asset_ids'][0]
    strURL = strBaseURL + strAPIFunction + strAssetID
    LogEntry("Querying for details on first AssetID in group {} out of {}:{}".format(
      iLineCount,iJSONLen,strAssetID))
    strResponse = ProcessAPI(strURL)
    objOutFile.write(strResponse)
    strAssetID = dictJSON['asset_ids'][1]
    strURL = strBaseURL + strAPIFunction + strAssetID
    LogEntry("Querying for details on second AssetID in group {} out of {}:{}".format(
      iLineCount,iJSONLen,strAssetID))
    strResponse = ProcessAPI(strURL)
    objOutFile.write(strResponse)
  
  LogEntry("Done!")
  objJSON.close()
  objOutFile.close()
  objLogOut.close()

if __name__ == '__main__':
  main()
