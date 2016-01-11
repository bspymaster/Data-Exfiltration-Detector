# NetworkHeuristics.py
# 
# A script written to analyze a set of pre-constructed DNS logs and find outliers and potential data exfiltration issues
# 
# Author:   Ben Schwabe

import glob
import os
import subprocess as sp

rootDirectory = "/full/path/to/folder/containing/folders/with/dated/logs/"

run = True
fileIterator = glob.iglob(rootDirectory+"*/dns.log") #rotates through all subdirectories and grabs any file named "dns.log" in those subdirectories

#contains pre-processed copies of all the data the software will work with
rawDataExists = os.path.isfile("raw_data.plog") #did the file exist
runningDataFile = open("raw_data.plog","a+") #opens file for reading and appending
#TODO: find a way to keep track of the last pieces of data logged and resume data calculations from that point

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
        targetFile = fileIterator.next()
    except StopIteration:
        run = False #fileIterator threw an error for no more files to go through
    except:
        raise #just in case a different error is thrown, call it normally
    
    if run:
        runningDataFile.write(sp.check_output("cat {0} | bro-cut -d ts id.orig_h id.resp_h id.resp_p")) #cats the file and bro-cuts the appropriate data into the runningDataFile for use
        #TODO: proper columns from file in bro-cuts

#TODO: scan through the runningDataFile and calculate statistics

runningDataFile.close()
