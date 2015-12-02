# NetworkHeuristics.py
# 
# A script written to analyze a set of pre-constructed DNS logs and find outliers and potential data exfiltration issues
# 
# Author:   Ben Schwabe
# Created:  2015.11.12
# Modified: 2015.11.12

import glob

rootDirectory = "/full/path/to/folder/containing/folders/with/dated/logs/"

#important columns

origin_ip_bytes = 23
responder_ip_bytes = 24

run = True
fileIterator = glob.iglob(rootDirectory+"*/dns.log")

#contains pre-processed copies of all the data the software will work with
#TODO: check for file existing
runningDataFile = open("raw_data.plog","r+")

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
    pvar = ss/n # the population variance
    return pvar**0.5

while run: #runs while more files in the fileIterator queue
    try:
        targetFile = fileIterator.next()
    except StopIteration:
        run = False
    except:
        raise
    
    if run:
        logFile = open(targetFile,"r")
        
        for line in logFile:
            if not (line[0] == "#"):
                lineArray = line.split("\t")
                if len(lineArray) != 27:
                    break #don't parse if the file doesn't have all the data we need
                else:
                    #TODO: brocut the logFile into the runningDataFile (starting where we left off if the logfile exists)
                    #the format of the parent loop may have to change depending on how the brocut works
                    #when brocutting to the new file, convert the timestamps into a python-readable format
                    pass
        
        logFile.close()

#TODO: scan through the runningDataFile and calculate statistics

runningDataFile.close()
