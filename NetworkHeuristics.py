# NetworkHeuristics.py
# 
# A script written to analyze a set of pre-constructed DNS logs and find outliers and potential data exfiltration issues
# 
# Author:   Ben Schwabe

from glob import glob
import os
import subprocess as sp
import datetime
from calendar import monthrange

#change this path to be the path to the server folder (one level out from the dated folders containing dns.log)
rootDirectory = "/full/path/to/folder/containing/folders/with/dated/logs/"

##############################
#PARSE DATA INTO RUNNING FILE#
##############################

fileList = sorted(glob(rootDirectory+"*/dns.log")) #crawls through all subdirectories and grabs any file named "dns.log" in those subdirectories, puts it in a list, and sorts it smallest to largest (oldest to newest)

#contains pre-processed copies of all the data the software will work with
#rawDataExists = os.path.isfile("raw_data.plog") #did the file exist
runningDataFile = open("raw_data.plog","a") #opens file for appending

#calculates the name of the folder that contains network data from the current day (so it knows what folder to skip)
todayFolder = str(datetime.date.today()) #calculates today's date and saves as a string (yyyy-mm-dd)
todayFolder = "".join(todayFolder.split("-")) #removes the hyphens from the name (yyyymmdd)

lastDate = -1 #FIXME: Change with calculations to pick up where it left off (keep as -1 if no file processed)

#contains data on folders that contain data not needed (either already read or incomplete files)
doNotReadDict = {"lastDateProcessed":lastDate,"today":todayFolder}

#crawls through sorted fileList
for fileObj in fileList:
    targetFileList = targetFile.replace("\\","/").split("/") #full path split into a list (handles Windows backslashes just in case)
    targetFileDate = targetFileList[len(targetFileList-2)] #finds the date of the file using its parent folder
    if targetFileDate != doNotReadList["today"] and int(targetFileDate) > doNotReadDict["lastDateProcessed"]: #if folder of current file is not from today and is newer than the last date already processed
        runningDataFile.write(sp.check_output("cat {0} | bro-cut -d ts id.orig_h id.resp_h id.resp_p orig_ip_bytes resp_ip_bytes".format(targetFile))) #cats the file and bro-cuts the appropriate data into the runningDataFile for use

runningDataFile.close()

################################
#CALCULATE AND ORGANIZE INTO DB#
################################

#TODO: scan through the runningDataFile and calculate statistics

#TODO: remove everything except the current month's data from the runningDataFile (since we won't need it and it keeps storage costs down and processing speeds up)

#TODO: write yesterday's date to a savefile as a "bookmark" for where the program left off
