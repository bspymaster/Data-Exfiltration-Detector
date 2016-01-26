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

#column indices after splitting a log line into a list
TS = 0
ORIG_H = 1
RESP_H = 2
RESP_P = 3
ORIG_IP_BYTES = 4
RESP_IP_BYTES = 5

#a class used to store information about the current operating set
class DataStorage:
    #initializes the class for use
    def __init__(self):
        self.reset()
    
    #resets the data back to defaults to be re-used
    def reset(self):
        self.numberEntries = 0
        
        self.meanSizeRequest = [-1.0,-1.0] #formatted: [meanSize,standardDev]
        self.meanSizeResponse = [-1.0,-1.0] #formatted: [meanSize,standardDev]
        self.ratioBytesInBytesOut = -1.0
        self.requests = {"topTenQuantity":["","","","","","","","","",""],"topTenSizeBytesOut":["","","","","","","","","",""],"topTenSizeBytesIn":["","","","","","","","","",""]}
        self.requesters = {"topTenQuantity":["","","","","","","","","",""],"topTenSizeBytesOut":["","","","","","","","","",""],"topTenSizeBytesIn":["","","","","","","","","",""]}
        
        self.totalSizeRequest = 0
        self.totalSizeResponse = 0
    
    #retrieves the mean size of the requests and the standard deviation
    #RETURN list: a list in the format [Mean Size (as a double),Standard Deviation (as a double)]
    def getMeanSizeRequest(self):
        self.meanSizeRequest[0] = self.totalSizeRequest/self.numberEntries
        #TODO: calculate standard deviation
        return self.meanSizeRequest
    
    #retrieves the mean size of the requesters and the standard deviation
    #RETURN list: a list in the format [Mean Size (as a double),Standard Deviation (as a double)]
    def getMeanSizeResponse(self):
        return self.meanSizeResponse
    
    #retrieves the the ratio of the mean size of the bytes in to the mean size of the bytes out 
    #RETURN double: a double denoting the ratio of the mean size of the bytes in to the mean size of the bytes out 
    def getRatioBytesIO(self):
        return self.ratioBytesInBytesOut
    
    #retrieves various data specific to requests made in the network
    #RETURN dictionary: a dictionary denoted by the following keys:
    #   "topTenQuantity" (which holds a list of 10 strings containing the top 10 requests by the amount of requests)
    #   "topTenSizeBytesOut" (which holds a list of 10 strings containing the top 10 requests of the largest requests sent out)
    #   "topTenSizeBytesIn" (which holds a list of 10 strings containing the top 10 requests of the largest requests received)
    def getRequestsData(self):
        return self.requests
    
    #retrieves various data specific to requesters made in the network
    #RETURN dictionary: a dictionary denoted by the following keys:
    #   "topTenQuantity" (which holds a list of 10 strings containing the top 10 requesters by the amount of requesters)
    #   "topTenSizeBytesOut" (which holds a list of 10 strings containing the top 10 requesters of the largest requests sent out)
    #   "topTenSizeBytesIn" (which holds a list of 10 strings containing the top 10 requesters of the largest requests received)
    def getRequestersData(self):
        return self.requesters
    
    #calculates more data into the entries based on a data set given
    #PARAM list logEntry: a list of information taken from a single line in a logfile
    def addData(self,logEntry):
        #TODO: process the data from the line and add it into the appropriate slots (may need to make a tree system of some sort for "top 10" data)
        self.numberEntries+=1#increment the amount of data added to the database
        self.addSizeRequest(logEntry)
        self.addSizeResponse(logEntry)
    
    #adds the size of the request (in bytes) to the total size (which can be later divided by the amount of entries logged to find the mean bytes)
    #PARAM list logEntry: a list of information taken from a single line in a logfile
    def addSizeRequest(self,logEntry):
        self.totalSizeRequest+=logEntry[ORIG_IP_BYTES]
    
    #adds the size of the request response (in bytes) to the total size (which can be later divided by the amount of entries logged to find the mean bytes)
    #PARAM list logEntry: a list of information taken from a single line in a logfile
    def addSizeResponse(self,logEntry):
        self.totalSizeResponse+=logEntry[RESP_IP_BYTES]

##############################
#PARSE DATA INTO RUNNING FILE#
##############################

#fileList = sorted(glob(rootDirectory+"*/dns.log")) #crawls through all subdirectories and grabs any file named "dns.log" in those subdirectories, puts it in a list, and sorts it smallest to largest (oldest to newest)

#contains pre-processed copies of all the data the software will work with
#rawDataExists = os.path.isfile("raw_data.plog") #did the file exist
#runningDataFile = open("raw_data.plog","a") #opens file for appending

#calculates the name of the folder that contains network data from the current day (so it knows what folder to skip)
todayFolder = str(datetime.date.today()) #calculates today's date and saves as a string (yyyy-mm-dd)
todayFolder = "".join(todayFolder.split("-")) #removes the hyphens from the name (yyyymmdd)

lastDate = -1 #FIXME: Change with calculations to pick up where it left off (keep as -1 if no file processed)

#contains data on folders that contain data not needed (either already read or incomplete files)
doNotReadDict = {"lastDateProcessed":lastDate,"today":todayFolder}

#crawls through sorted fileList (PRECOMPILER NOW DOES THIS)
#for fileObj in fileList:
#    targetFileList = targetFile.replace("\\","/").split("/") #full path split into a list (handles Windows backslashes just in case)
#    targetFileDate = targetFileList[len(targetFileList-2)] #finds the date of the file using its parent folder
#    if targetFileDate != doNotReadList["today"] and int(targetFileDate) > doNotReadDict["lastDateProcessed"]: #if folder of current file is not from today and is newer than the last date already processed
#        runningDataFile.write(sp.check_output("cat {0} | bro-cut -d ts id.orig_h id.resp_h id.resp_p orig_ip_bytes resp_ip_bytes".format(targetFile))) #cats the file and bro-cuts the appropriate data into the runningDataFile for use

runningDataFile.close()

################################
#CALCULATE AND ORGANIZE INTO DB#
################################

#structure to store data in
hourData = DataStorage()
dayData = DataStorage()

#used for calculating when to reset the data in the dataStorage classes
oldHour = None
oldDay = None
oldMonth = None
oldYear = None

#Scan through the runningDataFile and calculate statistics
#assumes all relevant logged data is pre-processed into a single bro-cut file called "dns.log" with columns ts, orig_h, resp_h, resp_p, orig_ip_bytes, and resp_ip_bytes
with open("dns.log","r") as runningDataFile: #automatically closes file at end
    for line in runningDataFile:
        logEntryList = line.split("\t")#split line into a list using tabs as a delimiter
        
        #bro-cut formats the timestamp into [yyyy]-[mm]-[dd]T[hh]:[mm]:[ss]+[mili]
        logEntryList[TS] = logEntryList[TS].replace("T","-").replace(":","-").replace("+","-")#formats the timestamp to be more usable by replacing "T", ":" and "+" with "-"
        logEntryList[TS] = logEntryList[TS].split("-")#splits the string into a list using "-" as a delimiter. List is now ["yyyy","mm","dd","hh","mm","ss","mili"]
        
        #once times change (i.e. new hour, new day, etc.), pull the data from the appropriate DataStorage instance, write to the proper file, and reset the class for next usage
        #FIXME: does not correctly log if "today" is a new hour/day/week/month (add "catch-all" to end of file?)
        #FIXME: re-do the key entries to a more arbitrary piece of data (incremental): yyyymmddxxxx where xxxx is an arbitrary (incremented?) number specific to that file only.
        #       This allows for calls to specific keys to go directly to the daily file it needs to access to find that key, saving time on filecrawling (only needs to crawl the daily file)
        #FIXME: may need to make folders if they do not exist yet
        if oldHour != None: #makes sure loop didn't just start
            if int(oldHour) < int(logEntryList[TS][3]):
                with open("db/{0}{1}/{0}{1}{2}.sdb".format(oldYear,oldMonth,oldDay),"a") as databaseFile:
                    asrequestData = hourData.getMeanSizeRequest()
                    databaseFile.write("{0}{1}{2}{3},hr,asrqst,{4},{5}".format(oldYear,oldMonth,oldDay,oldHour,asrequestData[0],asrequestData[1]))#average size request
                    asresponseData = hourData.getMeanSizeResponse()
                    databaseFile.write("{0}{1}{2}{3},hr,asrspns,{4},{5}".format(oldYear,oldMonth,oldDay,oldHour,asresponseData[0],asresponseData[1]))#average size response
                hourData.reset()
            if int(oldDay) < int(logEntryList[TS][2]):
                with open("db/{0}{1}/{0}{1}{2}.sdb".format(oldYear,oldMonth,oldDay),"a") as databaseFile:
                    asrequestData = dayData.getMeanSizeRequest()
                    databaseFile.write("{0}{1}{2}24,dy,asrqst,{3},{4}".format(oldYear,oldMonth,oldDay,asrequestData[0],asrequestData[1]))#average size request
                    asresponseData = dayData.getMeanSizeResponse()
                    databaseFile.write("{0}{1}{2}24,dy,asrspns,{3},{4}".format(oldYear,oldMonth,oldDay,asresponseData[0],asresponseData[1]))#average size response
                dayData.reset()
        
        oldHour = logEntryList[TS][3]
        oldDay = logEntryList[TS][2]
        oldMonth = logEntryList[TS][1]
        oldYear = logEntryList[TS][0]
        
        #add data to each class to be calcualted
        hourData.addData(logEntryList)
        dayData.addData(logEntryList)

#TODO: Log the hourly and daily data to files (since the last thing in the raw data will for sure be the last piece of data for yesterday)

#TODO: write yesterday's date to a savefile as a "bookmark" for where the program left off.
