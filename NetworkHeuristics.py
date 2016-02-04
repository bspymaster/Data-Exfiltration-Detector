#!usr/bin/python3

# NetworkHeuristics.py
# 
# A script written to analyze a set of pre-constructed DNS logs and find outliers and potential data exfiltration issues
# 
# Author:   Ben Schwabe

import sys

#checks for available version (ipaddress module included in 3.3 and after)
version = sys.version_info
if version[0] < 3 or (version[0] == 3 and version[1] < 3):
    raise OSError("You are not using the correct version of Python. Python 3.3 or higher is required for this program to execute.")

import os
import datetime
from calendar import monthrange
import ipaddress

#change this path to be the path to the folder containing the sorted dns.log
rootDirectory = "C:/Users/bspym/Dropbox/ITS/Data-Exfiltration-Detector/"
#/full/path/to/folder/containing/time/sorted/log/

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
        try:
            self.meanSizeRequest[0] = self.totalSizeRequest/self.numberEntries
            #TODO: calculate standard deviation
        except ZeroDivisionError:
            self.meanSizeRequest = [-1.0,-1.0] #no data logged for this time period
        return self.meanSizeRequest
    
    #retrieves the mean size of the requesters and the standard deviation
    #RETURN list: a list in the format [Mean Size (as a double),Standard Deviation (as a double)]
    def getMeanSizeResponse(self):
        try:
            self.meanSizeResponse[0] = self.totalSizeResponse/self.numberEntries
            #TODO: calculate standard deviation
        except ZeroDivisionError:
            self.meanSizeResponse = [-1.0,-1.0]
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
        #TODO: process the data from the line and add it into the appropriate slots (may need to make a tree system of some sort for "top 10" data or use mode on a list
        self.numberEntries+=1#increment the amount of data added to the database
        self.addSizeRequest(logEntry)
        self.addSizeResponse(logEntry)
    
    #adds the size of the request (in bytes) to the total size (which can be later divided by the amount of entries logged to find the mean bytes)
    #PARAM list logEntry: a list of information taken from a single line in a logfile
    def addSizeRequest(self,logEntry):
        self.totalSizeRequest+=int(logEntry[ORIG_IP_BYTES])
    
    #adds the size of the request response (in bytes) to the total size (which can be later divided by the amount of entries logged to find the mean bytes)
    #PARAM list logEntry: a list of information taken from a single line in a logfile
    def addSizeResponse(self,logEntry):
        self.totalSizeResponse+=int(logEntry[RESP_IP_BYTES])
    
    #gets the number of entries logged into the DataStorage
    #RETURN integer: the number of times addData() was called (i.e. the amount of lines of data added to the DataStorage instance)
    def getNumEntries(self):
        return self.numberEntries

###########################
#GET COMMANDLINE AGRUMENTS#
###########################

#Runs through the list of command line arguments
i=1
ipList = [] #list of all IP subnets to record (in CIDR notation)
while i < len(sys.argv):
    ipList.append(sys.argv[i].strip()) #append the ip to the list (strip any trailing whitespace)
    i += 1

if len(sys.argv) < 2:
    print("ERROR: One or more IPs must be defined in the command line arguments.")
    sys.exit(1)

#################################
#CALCULATE DATA TO AVOID READING#
#################################

#calculates the current day (so the program knows to avoid incomplete data from today)
todayDate = str(datetime.date.today()) #calculates today's date and saves as a string (yyyy-mm-dd)
todayDate = "".join(todayDate.split("-")) #removes the hyphens from the name (yyyymmdd)

lastDate = -1 #FIXME: Change with calculations to pick up where it left off (keep as -1 if no file processed)

#contains data on dates that contain data not needed (either already read or incomplete data for that time)
doNotReadDict = {"lastDayProcessed":lastDate,"today":todayDate}

################################
#CALCULATE AND ORGANIZE INTO DB#
################################

#create a list that holds all network data individually (since each network generates its own "table" of data)
ipDataList = []
for ip in ipList:
    ipDataList.append([DataStorage(),DataStorage()]) #appends [hour data, day data] data storage to  a list. The index of these lists corresponds to the index of the ip in ipList

#used for calculating when to reset the data in the dataStorage classes
oldHour = None
oldDay = None
oldMonth = None
oldYear = None

#used for generating new keys for each entry in the database (incremented by 1 for each entry & reset per day)
keyIndex = 0#note that str(keyIndex).zfill(4) will be used when appending leading zeros to this number (makes it a 4-digit numeric string)

#Scan through the runningDataFile and calculate statistics
#assumes all relevant logged data is pre-processed into a single bro-cut file called "dns.log" with columns ts, orig_h, resp_h, resp_p, orig_ip_bytes, and resp_ip_bytes with the data sorted by timestamp
with open("{0}dns.log".format(rootDirectory),"r") as runningDataFile: #automatically closes file at end
    for line in runningDataFile:
        logEntryList = line.split("\t")#split line into a list of strings using tabs as a delimiter
        
        #bro-cut formats the timestamp into [yyyy]-[mm]-[dd]T[hh]:[mm]:[ss]+[mili]
        logEntryList[TS] = logEntryList[TS].replace("T","-").replace(":","-").replace("+","-")#formats the timestamp to be more usable by replacing "T", ":" and "+" with "-"
        logEntryList[TS] = logEntryList[TS].split("-")#splits the string into a list using "-" as a delimiter. List is now ["yyyy","mm","dd","hh","mm","ss","mili"]
        dayString = "{0}{1}{2}".format(logEntryList[TS][0],logEntryList[TS][1],logEntryList[TS][2])#used to compare to doNotReadDict
        
        oldHourString = "{0}{1}{2}{3}".format(oldYear,oldMonth,oldDay,oldHour)#creates string yyyymmddhh for database logging
        oldDayString = "{0}{1}{2}".format(oldYear,oldMonth,oldDay)#creates string yyyymmdd for database logging
        
        #once times change (i.e. new hour, new day, etc.), pull the data from the appropriate DataStorage instance, write to the proper file, and reset the class for next usage
        #FIXME: does not log the last day/hour in the file before EOF
        if oldHour != None: #avoids processing data at the wrong times (i.e. the loop just started, or processing data from today when there might be incomplete data)
            
            for i in range(0,len(ipList)):
                fileSafeIP = ipList[i].replace(".","_").replace("/","S")#the ip will be in the format 123_456_789_012S34 if the ip is 123.456.789.012/34 (cidr notation)
                
                if int(oldHour) != int(logEntryList[TS][3]) and ipDataList[i][0].getNumEntries() > 0:#hour changed and there is data to log
                    #make path if it does not exist
                    if not os.path.exists("db/{0}/{1}{2}".format(fileSafeIP,oldYear,oldMonth)):
                        os.makedirs("db/{0}/{1}{2}".format(fileSafeIP,oldYear,oldMonth))
                    
                    #write data
                    with open("db/{0}/{1}{2}/{1}{2}{3}.sdb".format(fileSafeIP,oldYear,oldMonth,oldDay),"a") as databaseFile:
                        asrequestData = ipDataList[i][0].getMeanSizeRequest()
                        databaseFile.write("{0}{1},{2},hr,asrqst,{3},{4}\n".format(oldDayString,str(keyIndex).zfill(4),oldHourString,asrequestData[0],asrequestData[1]))#average size request
                        keyIndex+=1
                        
                        asresponseData = ipDataList[i][0].getMeanSizeResponse()
                        databaseFile.write("{0}{1},{2},hr,asrspns,{3},{4}\n".format(oldDayString,str(keyIndex).zfill(4),oldHourString,asresponseData[0],asresponseData[1]))#average size response
                        keyIndex+=1
                    
                    ipDataList[i][0].reset()
                if int(oldDay) != int(logEntryList[TS][2]) and ipDataList[i][1].getNumEntries() > 0:#day changed and there is data to log
                    #make path if it does not exist
                    if not os.path.exists("db/{0}/{1}{2}".format(fileSafeIP,oldYear,oldMonth)):
                        os.makedirs("db/{0}/{1}{2}".format(fileSafeIP,oldYear,oldMonth))
                    
                    #write data
                    with open("db/{0}/{1}{2}/{1}{2}{3}.sdb".format(fileSafeIP,oldYear,oldMonth,oldDay),"a") as databaseFile:
                        asrequestData = ipDataList[i][1].getMeanSizeRequest()
                        databaseFile.write("{0}{1},{2}00,dy,asrqst,{3},{4}\n".format(oldDayString,str(keyIndex).zfill(4),oldDayString,asrequestData[0],asrequestData[1]))#average size request
                        keyIndex+=1
                        
                        asresponseData = ipDataList[i][1].getMeanSizeResponse()
                        databaseFile.write("{0}{1},{2}00,dy,asrspns,{3},{4}\n".format(oldDayString,str(keyIndex).zfill(4),oldDayString,asresponseData[0],asresponseData[1]))#average size response
                        keyIndex+=1
                    
                    ipDataList[i][1].reset()
                    keyIndex = 0#re-use key suffix since the day changed (even though it is still potentially in the same table)
        
        #re-calculate old timestamp for use on next iteration if the lastDayProcessed is less than the current entry being accessed
        if doNotReadDict["lastDayProcessed"] < int(dayString):
            oldHour = logEntryList[TS][3]
            oldDay = logEntryList[TS][2]
            oldMonth = logEntryList[TS][1]
            oldYear = logEntryList[TS][0]
            
        #set the times to None so incomplete data from today is not written to the database
        if doNotReadDict["today"] == int(dayString):
            oldHour = None
            oldDay = None
            oldMonth = None
            oldYear = None
        
        #add data to each class to be calcualted, if the data is past the last entries already in the database
        if doNotReadDict["lastDayProcessed"] < int(dayString) and doNotReadDict["today"] != int(dayString):
            i = 0#index of ipDataList
            for cidrip in ipList:
                if ipaddress.ip_address(logEntryList[ORIG_H]) in ipaddress.ip_network(cidrip):#checks to make sure the origin IP is one of the IPs being searched
                    ipDataList[i][0].addData(logEntryList)
                    ipDataList[i][1].addData(logEntryList)
                i+=1#next index in ipDataList

#TODO: write yesterday's date to a savefile as a "bookmark" for where the program left off.
