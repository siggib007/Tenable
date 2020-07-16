'''
Script to parse Tenable Plugin ID 19506 output
Version: 1.0
Author Siggi Bjarnason Copyright 2020

Following packages need to be installed as administrator

'''
# Import libraries
import sys
import os
import string
import time
import csv

try:
  import tkinter as tk
  from tkinter import filedialog
  btKinterOK = True
except:
  print ("Failed to load tkinter, CLI only mode.")
  btKinterOK = False
# End imports

def getInput(strPrompt):
  if sys.version_info[0] > 2 :
    return input(strPrompt)
  else:
    LogEntry("Please upgrade to python 3.x")
    sys.exit()
# end getInput

def LogEntry(strMsg):
  print (strMsg)

def CleanStr(strOld):
  strTemp = strOld.replace('"','')
  strTemp = strTemp.replace(',','')
  strTemp = strTemp.replace('\n','')
  return strTemp.strip()

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

def main():
  # Initialize stuff
  strDelim = ","          # what is the field seperate in the input file
  strCSVName = ""
  objOutFile = open("/temp/19506stats.csv","w",1)
  #Start doing stuff
  print ("This is a script to parse the output from Tenable Plugin ID 19506. This is running under Python Version {0}.{1}.{2}".format(sys.version_info[0],sys.version_info[1],sys.version_info[2]))
  now = time.asctime()
  print ("The time now is {}".format(now))

  sa = sys.argv

  lsa = len(sys.argv)
  if lsa > 1:
    strCSVName = sa[1]

  if strCSVName == "":
    if btKinterOK:
      print ("File name to be imported is missing. Opening up a file open dialog box, please select the file you wish to import.")
      root = tk.Tk()
      root.withdraw()
      strCSVName = filedialog.askopenfilename(title = "Select CSV file",filetypes = (("CSV files","*.csv"),("Text files","*.txt"),("all files","*.*")))
    else:
      strCSVName = getInput("Please provide full path and filename for the CSV file to be imported: ")

  if strCSVName == "":
    print ("No filename provided unable to continue")
    sys.exit()

  if os.path.isfile(strCSVName):
    print ("OK found {}".format(strCSVName))
  else:
    print ("Can't find CSV file {}".format(strCSVName))
    sys.exit(4)

  iLineCount = 0
  iTotalScan = 0
  with open(strCSVName,newline="") as hCSV:
    myReader = csv.reader(hCSV, delimiter=strDelim)
    lstLine = next(myReader)
    lstHeaders = []
    dictDur = {}
    dictCount = {}
    lstHeaders.append(lstLine[0])
    lstHeaders.append(lstLine[3])

    for lstLine in myReader :
      lstLine = next(myReader)
      lstStats = []
      lstStats.append(lstLine[0])
      lstStats.append(lstLine[3])
      lstOutput = lstLine[12].splitlines()
      del lstOutput[0]
      del lstOutput[0]
      for strLine in lstOutput:
        strLineParts = strLine.split(": ")
        if len(strLineParts) > 1:
          lstHeaders.append(CleanStr(strLineParts[0]))
          if strLineParts[0].strip() == "Port range":
            strTemp = strLineParts[1].replace(",","|")
            lstStats.append(CleanStr(strTemp))
          elif strLineParts[0].strip() == "Scan duration":
            iScanDur = int(strLineParts[1][:-4])
            iTotalScan += iScanDur
            lstStats.append(str(iScanDur))
          else:
            lstStats.append(CleanStr(strLineParts[1]))
      if iLineCount == 0:
        objOutFile.write("{}\n".format(",".join(lstHeaders)))
      objOutFile.write("{}\n".format(",".join(lstStats)))
      if lstStats[6] in dictCount:
        dictCount[lstStats[6]] += 1
      else:
        dictCount[lstStats[6]] = 1
      if lstStats[6] in dictDur:
        dictDur[lstStats[6]] += iScanDur
      else:
        dictDur[lstStats[6]] = iScanDur
      iLineCount += 1
      print ("Processed {} lines....".format(iLineCount),end="\r")
  strOut = "\n\nScan Policy,Count,Duration,Avg Sec,Ave Min"
  print(strOut)
  objOutFile.write ("{}\n".format(strOut))
  for strPolicy in dictCount:
    iAvgSec = dictDur[strPolicy]/dictCount[strPolicy]
    iAvgMin = iAvgSec/60
    strOut = ("{},{},{},{:.2f},{:.2f}".format(strPolicy, dictCount[strPolicy],dictDur[strPolicy],iAvgSec,iAvgMin))
    print (strOut)
    objOutFile.write ("{}\n".format(strOut))
  
  
  iAvgSec = iTotalScan/iLineCount
  iAvgMin = iAvgSec/60
  strOut = ("\n\nTotal scans: {}\nTotal Scan Dur: {} sec\nAverage {:.2f} sec per scan or {:.2f} min".format(iLineCount,iTotalScan,iAvgSec,iAvgMin))
  print (strOut)
  objOutFile.write ("{}\n".format(strOut))
  objOutFile.close()


if __name__ == '__main__':
  main()

