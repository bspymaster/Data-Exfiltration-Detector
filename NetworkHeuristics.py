# NetworkHeuristics.py
# 
# A script written to analyze a set of pre-constructed DNS logs and find outliers and potential data exfiltration issues
# 
# Author:   Ben Schwabe

import glob
import os
import subprocess as sp
import datetime

rootDirectory = "/full/path/to/folder/containing/folders/with/dated/logs/"

run = True
fileIterator = glob.iglob(rootDirectory+"*/dns.log") #rotates through all subdirectories and grabs any file named "dns.log" in those subdirectories

#contains pre-processed copies of all the data the software will work with
rawDataExists = os.path.isfile("raw_data.plog") #did the file exist
runningDataFile = open("raw_data.plog","a") #opens file for appending

#calculates the name of the folder that contains network data from the current day
todayFolder = str(datetime.date.today()) #calculates today's date and saves as a string (yyyy-mm-dd)
todayFolder = "".join(todayFolder.split("-")) #removes the hyphens from the name (yyyymmdd)

TEMP = 0 #FIXME: change with last date processed into runningDataFile (set to 0 if reunningDataFile doesn't exist)

#contains data on folders that contain data not needed (either already read or incomplete files)
doNotReadDict = {"lastDateProcessed":TEMP,"today":todayFolder}

#Return the sample arithmetic mean of data.
def mean(data):
    n = len(data)
    if n < 1:
        raise ValueError('mean requires at least one data point')
    return sum(data)/float(n)

#Return sum of square deviations of sequence data.
def sumSquare(data):
    avg = mean(data)
    sumData = sum((i-avg)**2 for i in data)
    return sumData

#Calculates the standard deviation.
def stdev(data):
    n = len(data)
    if n < 2:
        raise ValueError('variance requires at least two data points')
    ss = sumSquare(data)
    pvar = ss/n #the population variance
    return pvar**0.5

while run: #runs while more files in the fileIterator queue
    try:
        targetFile = fileIterator.next() #file with full path
        targetFileList = targetFile.split("/")
        targetFileDate = targetFileList[len(targetFileList-2)]
    except StopIteration:
        run = False #fileIterator threw an error for no more files to go through
    except:
        raise #just in case a different error is thrown, call it normally
    
    if run: #makes sure the loop is still active
        if targetFileDate != doNotReadList["today"] and int(targetFileDate) > doNotReadDict["lastDateProcessed"]: #if folder of current file is not from today and is newer than the last date already processed
            runningDataFile.write(sp.check_output("cat {0} | bro-cut -d ts id.orig_h id.resp_h id.resp_p orig_ip_bytes resp_ip_bytes".format(targetFile))) #cats the file and bro-cuts the appropriate data into the runningDataFile for use

runningDataFile.close()

#TODO: scan through the runningDataFile and calculate statistics

#TODO: write yesterday's date to a savefile as a "bookmark" for where the program left off
