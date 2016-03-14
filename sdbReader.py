#!/usr/bin/python3

# sdbReader.py
#
# Reads the data from a .sdb formatted database and writes the information into a visual Google Charts html page
#
# Author:   Ben Schwabe

import glob

#local directory used to start when reading from .sdb files from, as well as where to write the HTML visual page
rootDirectory = "C:/Users/bspym/Dropbox/ITS/Data-Exfiltration-Detector/"

#compile a list of networks to compile data
networkList = []
with open("db/info.sdbd","r") as ipInfoDoc:
    for line in ipInfoDoc:
        networkList.append(line.split(":")[0]) #grab network name from each line

#####################
#construct .CSS file#
#####################

with open("db/styles.css","w") as cssDoc:
    cssDoc.write("h1,h4{\n\ttext-align:center;\n}\n\n#ratio_chart,#asreq_chart,#asresp_chart{\n\twidth:915px;\n\theight:300px;\n}\n#ratio_filter,#asreq_filter,#asresp_filter{\n\twidth:915px;\n\theight:50px;\n}\n")

######################
#construct index page#
######################
#containing a list of all the visual documents created

with open("db/index.html","w") as indexDoc:
    #header
    indexDoc.write('<html>\n\t<head>\n\t\t<title>Index</title>\n\t\t<link rel="stylesheet" href="styles.css">\n\t</head>\n\t<body>\n\t\t<h1>Visual Data</h1>\n\t\t<hr />\n\t\t<p>Data has been compiled visually for the following IP networks:</p>\n\t\t<ul>\n')
    #list of IP networks
    for network in networkList:
        networkFolderName = network.replace(".","_").replace("/","S")#constructs appropriate folder name for each network
        indexDoc.write('\t\t\t<li><a href="{0}/visualData.html">{1}</a></li>\n'.format(networkFolderName,network))
    #footer
    indexDoc.write('\t\t</ul>\n\t</body>\n</html>\n')

#############################
#construct visualData pages#
#############################
#for all available networks logged

for network in networkList:
    networkFolderName = network.replace(".","_").replace("/","S")#constructs appropriate folder name for each network
    with open("db/{0}/visualData.html".format(networkFolderName),"w") as dataPage:
        #write standard HTML head data
        dataPage.write('<html>\n\t<head>\n\t\t<title>{0}</title>\n\t\t<link rel="stylesheet" href="../styles.css">\n\t\t<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>\n\t\t<script type="text/javascript">\n'.format(network))
        
        #write standard javascript head
        dataPage.write("\t\t\t//Chart data\n\t\t\tgoogle.charts.load('44',{'packages':['controls','corechart']});\n\t\t\tgoogle.charts.setOnLoadCallback(drawDashboard);\n\n\t\t\tfunction drawDashboard(){\n\t\t\t\tvar masterDataSet = google.visualization.arrayToDataTable([\n\t\t\t\t\t[{label:'date',type:'datetime'},{label:'Bytes from network:Bytes to network',type:'number'},{label:'average request size',type:'number'},{label:'average size response',type:'number'}],\n")#FIXME: currently loads google API 44 (character column 70&71), should change this to "current" once Google fixes their API issues
        
        #construct a list of all database files for that network
        fileList = glob.glob("db/{0}/*/*.sdb".format(networkFolderName))
        fileList.sort()#sorts file list oldest to newest
        
        #read through database files and compile data
        dayDataList = [[0,0,0],0,0,0] #[[yyyy,mm,dd],ratioBytesIO,avgSizeRequest,avgSizeResp]
        dayFinishedFlag = 3 #will not write to html file until all the data from the dataFile for the day is compiled
        for fileName in fileList:
            with open(fileName,"r") as fileObj:
                for line in fileObj:
                    lineList = line.strip().split(",")
                    if lineList[3] == "rbytesio" and lineList[2] == "dy":
                        dayDataList[0][0] = lineList[1][0:4]#yyyy
                        dayDataList[0][1] = lineList[1][4:6]#mm
                        dayDataList[0][2] = lineList[1][6:8]#dd
                        dayDataList[1] = lineList[4] #data
                        dayFinishedFlag -= 1 #one less thing to record
                    elif lineList[3] == "asrqst" and lineList[2] == "dy":
                        dayDataList[2] = lineList[4] #data
                        dayFinishedFlag -= 1 #one less thing to record
                    elif lineList[3] == "asrspns" and lineList[2] == "dy":
                        dayDataList[3] = lineList[4] #data
                        dayFinishedFlag -= 1 #one less thing to record
            
            #write to file if dayFinishedFlag is 0 (should pass unless it missed data somehow); acts as a final screen for incomplete data
            if not dayFinishedFlag:
                dataPage.write("\t\t\t\t\t[new Date({0},{1},{2},00,00),{3},{4},{5}],\n".format(dayDataList[0][0],dayDataList[0][1],dayDataList[0][2],dayDataList[1],dayDataList[2],dayDataList[3]))
                dayFinishedFlag = 3;
        
        #write standard javascript footer
        dataPage.write("\t\t\t\t]);\n\t\t\t\t\n\t\t\t\tvar dashboard = new google.visualization.Dashboard(document.getElementById('dashboard_div'));\n\t\t\t\t\n")
        
        dataPage.write("\t\t\t\t//MASTER CONTROLS\n\t\t\t\tvar dateRangeFilter_all = new google.visualization.ControlWrapper({'controlType':'ChartRangeFilter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'containerId':'all_filter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'options':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'filterColumnLabel':'date',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'ui':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartOptions':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'colors': ['blue','red','orange'],\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartArea':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'width':'90%'\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   });\n\t\t\t\t\n")
                dataPage.write("\t\t\t\t//RATIO GRAPH\n\t\t\t\tvar dateRangeFilter_ratio = new google.visualization.ControlWrapper({'controlType':'ChartRangeFilter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'containerId':'ratio_filter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'options':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'filterColumnLabel':'date',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'ui':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartOptions':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'colors': ['blue'],\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartArea':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'width':'90%'\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t},\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t'view':{'columns':[0,1]}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   });\n\t\t\t\tvar lineChart_ratio = new google.visualization.ChartWrapper({'chartType':'LineChart',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'containerId':'ratio_chart',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'options':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'colors': ['blue'],\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'title': 'Total Bytes from the Source Network to Total Bytes To the Source Network per Day',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'curveType': 'function',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartArea': {'height': '80%', 'width': '90%'},\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'legend': 'none'\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   }\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t  });\n\t\t\t\tdashboard.bind(dateRangeFilter_ratio,lineChart_ratio);\n\t\t\t\t\n")        
        dataPage.write("\t\t\t\t//AVERAGE SIZE REQUEST GRAPH\n\t\t\t\tvar dateRangeFilter_asreq = new google.visualization.ControlWrapper({'controlType':'ChartRangeFilter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'containerId':'asreq_filter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'options':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'filterColumnLabel':'date',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'ui':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartOptions':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'colors': ['red'],\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartArea':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'width':'90%'\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t},\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t'view':{'columns':[0,2]}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   });\n\t\t\t\tvar lineChart_asreq = new google.visualization.ChartWrapper({'chartType':'LineChart',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'containerId':'asreq_chart',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'options':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'colors': ['red'],\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'title': 'Average size of DNS request per day',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'curveType': 'function',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartArea': {'height': '80%', 'width': '90%'},\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'legend': 'none'\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   }\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t  });\n\t\t\t\tdashboard.bind(dateRangeFilter_asreq,lineChart_asreq);\n\t\t\t\t\n")
        dataPage.write("\t\t\t\t//AVERAGE SIZE RESPONSE GRAPH\n\t\t\t\tvar dateRangeFilter_asresp = new google.visualization.ControlWrapper({'controlType':'ChartRangeFilter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'containerId':'asresp_filter',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'options':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'filterColumnLabel':'date',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'ui':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartOptions':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'colors': ['orange'],\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartArea':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'width':'90%'\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t},\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t'view':{'columns':[0,3]}\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   });\n\t\t\t\tvar lineChart_asresp = new google.visualization.ChartWrapper({'chartType':'LineChart',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'containerId':'asresp_chart',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'options':{\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'colors': ['orange'],\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'title': 'Average size of DNS response per day',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'curveType': 'function',\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'chartArea': {'height': '80%', 'width': '90%'},\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   'legend': 'none'\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   }\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t  });")

        dataPage.write("\n\t\t\t\tdashboard.bind(dateRangeFilter_asresp,lineChart_asresp);\n\t\t\t\t\n\t\t\t\t//bind all to the master controls\n\t\t\t\tdashboard.bind([dateRangeFilter_all],[dateRangeFilter_ratio,lineChart_ratio,dateRangeFilter_asreq,lineChart_asreq,dateRangeFilter_asresp,lineChart_asresp])\n\t\t\t\t\n\t\t\t\tdashboard.draw(masterDataSet);\n\t\t\t}\n")
        
        #write standard HTML foot data
        dataPage.write('\t\t</script>\n\t</head>\n\t<body>\n\t\t<h1>Data for {0}</h1>\n\t\t<hr />\n\t\t<a href="../index.html">&lt&ltBACK TO INDEX</a>\n\t\t<div id="dashboard_div">\n\t\t\t<table>\n\t\t\t\t<tr>\n\t\t\t\t\t<td>\n\t\t\t\t\t\t<h4>Select date range for all graphs</h4>\n\t\t\t\t\t\t<div id="all_filter"></div>\n\t\t\t\t\t</td>\n\t\t\t\t\t<td>\n\t\t\t\t\t\t<div id="ratio_chart"></div>\n\t\t\t\t\t\t<div id="ratio_filter"></div>\n\t\t\t\t\t</td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td>\n\t\t\t\t\t\t<div id="asreq_chart"></div>\n\t\t\t\t\t\t<div id="asreq_filter"></div>\n\t\t\t\t\t</td>\n\t\t\t\t\t<td>\n\t\t\t\t\t\t<div id="asresp_chart"></div>\n\t\t\t\t\t\t<div id="asresp_filter"></div>\n\t\t\t\t\t</td>\n\t\t\t\t<tr>\n\t\t\t</table>\n\t\t</div>\n\t</body>\n</html>\n'.format(network))
