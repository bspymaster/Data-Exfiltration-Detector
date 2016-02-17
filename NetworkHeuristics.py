#!usr/bin/python2

# NetworkHeuristics.py
# 
# A script written to analyze a set of pre-constructed DNS logs and find outliers and potential data exfiltration issues
# 
# Author:   Ben Schwabe

import sys
import os
import datetime
from calendar import monthrange

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
        self.entryList = []
        
        self.meanSizeRequest = [-1.0,0.0] #formatted: [meanSize,standardDev]
        self.meanSizeResponse = [-1.0,0.0] #formatted: [meanSize,standardDev]
        self.ratioBytesInBytesOut = -1.0
        self.requests = {"topTenQuantity":[],"topTenSizeBytesOut":[],"topTenSizeBytesIn":[]} #each list contains 10 ip strings
        self.requesters = {"topTenQuantity":[],"topTenSizeBytesOut":[],"topTenSizeBytesIn":[]} #each list contains 10 ip strings
    
    #retrieves the mean size of the requests and the standard deviation
    #RETURN list: a list in the format [Mean Size (as a double),Standard Deviation (as a double)]
    def getMeanSizeRequest(self):
        lengthEntryList = len(self.entryList)
        if lengthEntryList < 1:
            self.meanSizeRequest = [-1.0,0.0] #no data logged for this time period
        else:
            total = 0.0
            for obj in self.entryList:
                total += int(obj[ORIG_IP_BYTES]) #total bytes over the time period
            self.meanSizeRequest[0] = total/float(lengthEntryList) #calculate mean
            if lengthEntryList < 2:
                self.meanSizeRequest[1] = 0.0 #need at least 2 points for standard deviation
            else: #calculate standard deviation
                sumSqrDev = 0.0
                for obj in self.entryList:
                    sumSqrDev += (int(obj[ORIG_IP_BYTES]) - self.meanSizeRequest[0])**2#sum of the square deviations for the data set
                self.meanSizeRequest[1] = (sumSqrDev/lengthEntryList)**0.5 #square root of the population variance (the standard deviation)
        return self.meanSizeRequest
    
    #retrieves the mean size of the requesters and the standard deviation
    #RETURN list: a list in the format [Mean Size (as a double),Standard Deviation (as a double)]
    def getMeanSizeResponse(self):
        lengthEntryList = len(self.entryList)
        if lengthEntryList < 1:
            self.meanSizeResponse = [-1.0,0.0] #no data logged for this time period
        else:
            total = 0.0
            for obj in self.entryList:
                total += int(obj[RESP_IP_BYTES]) #total bytes over the time period
            self.meanSizeResponse[0] = total/float(lengthEntryList) #calculate mean
            if lengthEntryList < 2:
                self.meanSizeResponse[1] = 0.0 #need at least 2 points for standard deviation
            else: #calculate standard deviation
                sumSqrDev = 0.0
                for obj in self.entryList:
                    sumSqrDev += (int(obj[RESP_IP_BYTES]) - self.meanSizeRequest[0])**2#sum of the square deviations for the data set
                self.meanSizeResponse[1] = (sumSqrDev/lengthEntryList)**0.5 #square root of the population variance (the standard deviation)
        return self.meanSizeResponse
    
    #retrieves the ratio of the total number of bytes from the origin to the total number of bytes of the response 
    #RETURN float: a floating point number denoting the ratio of the number of bytes from the origin network to the number of bytes from the responder 
    def getRatioBytesIO(self):
        totalBytesOrigin = 0.0
        totalBytesResponse = 0.0
        
        for entry in self.entryList:
            totalBytesOrigin += int(entry[ORIG_IP_BYTES])
            totalBytesResponse += int(entry[RESP_IP_BYTES])
        
        self.ratioBytesInBytesOut = totalBytesOrigin/totalBytesResponse #calculate ratio as float, since totalBytesOrigin and totalBytesResponse are boath floats
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
        self.entryList.append(logEntry)
    
    #gets the number of entries logged into the DataStorage
    #RETURN integer: the number of times addData() was called (i.e. the amount of lines of data added to the DataStorage instance)
    def getNumEntries(self):
        return len(self.entryList)

###########################
#GET COMMANDLINE AGRUMENTS#
###########################

#Runs through the list of command line arguments
i=1
ipList = [] #list of all IP subnets to record (in CIDR notation)
while i < len(sys.argv):
    if ("/" in sys.argv[i].strip()) and not ("/24" in sys.argv[i].strip()):#if the ip has a cidr slash, but is not /24, throw an error
        print "ERROR: invalid ip /24 network '{0}'.".format(sys.argv[i])
        sys.exit(1)
    ipList.append(sys.argv[i].strip()) #append the ip to the list (strip any trailing whitespace)
    i += 1

if len(sys.argv) < 2:
    print "ERROR: One or more IPs must be defined in the command line arguments."
    sys.exit(1)

#################################
#CALCULATE DATA TO AVOID READING#
#################################

#contains data on dates that contain data not needed (either already read or incomplete data for that time)
doNotReadDict = {}

#calculates the current day (so the program knows to avoid incomplete data from today)
todayDate = str(datetime.date.today()) #calculates today's date and saves as a string (yyyy-mm-dd)
todayDate = "".join(todayDate.split("-")) #removes the hyphens from the name (yyyymmdd)
doNotReadDict["today"] = todayDate

#check to see if the sdb data file exists
doNotReadDict["lastDayProcessed"] = [-1 for elem in ipList] #fills all last days processed for the corresponding IPs in ipList with -1 (no last date)
if not os.path.exists("db/"): #data file doesnt exist
    os.makedirs("db") #make a directory for later use
    if os.path.exists("db/info.sdbd"): #data file exists
        with open("db/info.sdbd","r") as dataFile:
            with open("db/info.sdbd.tmp","w") as tempDataFile: #temporary file to copy data from the info over (ignores IPs being searched for, since those IPs will have to have their date updated)
                for line in dataFile:
                    lineArray = line.split(":")#first element is cidr ip, second is last date written in db
                    lineArray[0] = ".".join(lineArray[0].split(".")[0:3])#compiles the first three octets into an "ip" (since we can ignore the last octet, assuming /24 network)
                    i = 0
                    found = False #flag to mark if the ip was found
                    for ip in ipList:
                        if lineArray[0] in ip:
                            doNotReadDict["lastDayProcessed"][i] = int(lineArray[1])#found a matching /24 network previously searched, change lastDayProcessed for that ip (index of lastDatProcessed corresponds with index of ipList)
                            found = True
                            break
                        i+=1
                    if not found:
                        tempDataFile.write(line)#ip wasn't found on this line, so leave existing data alone (by copying it over into the new file)
                        

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
        if oldHour != None: #avoids processing data at the wrong times (i.e. the loop just started, or processing data from today, when there might be incomplete data)
            
            for i in range(0,len(ipList)):
                fileSafeIP = ipList[i].replace(".","_")#the ip will be in the format 123_456_789_012S34 if the ip is 123.456.789.012/34 (cidr notation)
                fileSafeIP = fileSafeIP + "S24"#assumes /24 network
                
                if (int(oldHour) < int(logEntryList[TS][3]) or int(oldDay) != int(logEntryList[TS][2])) and ipDataList[i][0].getNumEntries() > 0:#hour changed and there is data to log
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
                        
                        ratioData = ipDataList[i][0].getRatioBytesIO()
                        databaseFile.write("{0}{1},{2},hr,rbytesio,{3}\n".format(oldDayString,str(keyIndex).zfill(4),oldHourString,ratioData))#ratio of total bytes from network to total bytes from response
                        keyIndex+=1
                    
                    ipDataList[i][0].reset()
                if int(oldDay) < int(logEntryList[TS][2]) and ipDataList[i][1].getNumEntries() > 0:#day changed and there is data to log
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
                        
                        ratioData = ipDataList[i][1].getRatioBytesIO()
                        databaseFile.write("{0}{1},{2}00,dy,rbytesio,{3}\n".format(oldDayString,str(keyIndex).zfill(4),oldDayString,ratioData))#ratio of total bytes from network to total bytes from response
                        keyIndex+=1
                    
                    ipDataList[i][1].reset()
                    keyIndex = 0#re-use key suffix since the day changed (even though it is still potentially in the same table)
        
        #re-calculate old timestamp for use on next iteration if the lastDayProcessed is less than the current entry being accessed
        for i in range(0,len(ipList)):
            if doNotReadDict["lastDayProcessed"][i] < int(dayString): #at least one IP being searched is past the last date recorded, so keep track of old dates
                oldHour = logEntryList[TS][3]
                oldDay = logEntryList[TS][2]
                oldMonth = logEntryList[TS][1]
                oldYear = logEntryList[TS][0]
                break
            
        #set the times to None so incomplete data from today is not written to the database
        if doNotReadDict["today"] == int(dayString):
            oldHour = None
            oldDay = None
            oldMonth = None
            oldYear = None
        
        #add data to each class to be calcualted, if the data is past the last entries already in the database and not data from today
        if doNotReadDict["today"] != int(dayString):
            i = 0#index of ipDataList
            for cidrip in ipList:
                if doNotReadDict["lastDayProcessed"][i] < int(dayString):
                    cidrIpList = cidrip.split(".")#split into list
                    cidrIpList = [cidrIpList[0],cidrIpList[1],cidrIpList[2]]#grab the first 3 octets
                    cidrip = ".".join(cidrIpList)#make into a string to compare
                    
                    if cidrip in logEntryList[ORIG_H]:#checks to make sure the origin IP is one of the IPs being searched (assumes /24 network)
                        ipDataList[i][0].addData(logEntryList)
                        ipDataList[i][1].addData(logEntryList)
                i+=1#next index in ipDataList

yesterday = datetime.date.today() - datetime.timedelta(days=1)#calculate yesterday's date
yesterdayString = str(yesterday)
yesterdayString = "".join(yesterdayString.split("-"))#converts yesterday to yyyymmdd

#open the tempDataFile and append the updated networks and dates to the file.
with open("db/info.sdbd.tmp","a") as tempDataFile:
    for cidrip in ipList:
        tempDataFile.write("{0}:{1}\n".format(cidrip,yesterdayString))
if os.path.exists("db/info.sdbd"):
    os.remove("db/info.sdbd")#removes the old data file
os.rename("db/info.sdbd.tmp","db/info.sdbd")#changes the temporary data file to the name of the permanent one
