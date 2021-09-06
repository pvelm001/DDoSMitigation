# This program is to identify and mitigate DoS attack on Mininet enviroinment 

import math
import pyshark
import multiprocessing
import time

import csv

import pandas as pd
from sklearn.cluster import KMeans

from collections import Counter


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

# Global Variables

ErrorList = []

IP_ADD = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
MAC_ADD = ['00:00:00:00:00:01', '00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04']


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

# This Function is to run the capturePackets for 10 second window               

def startProcess() :

    print("1")
    
    try :
        
        # Start Capturing as a process
        C = multiprocessing.Process(target=capturePackets, name="Capture", args=(10,))
        C.start()

        # Wait 10 seconds for Capture
        C.join(10)
    
        if C.is_alive():
            # Terminate foo
            C.terminate()
            C.join()

                
        # This is to invoke the next process
        kMeansPreprocess() 
            
    except Exception as e :

        print("startProcess() Error : \n MSG: ", e)


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

# This Function is to capture live packets by pyshark module
def capturePackets(self) : 

    print("2")
    
    # We can filter the traces below
    Live_Capture = pyshark.LiveCapture(interface = 'any')

    # Write mode creates the file if !exists

    try:
        with open('capturePackets_Output.csv', 'w', newline='') as f:
            csvWriter = csv.writer(f)
            csvWriter.writerow(['SRC IP', 'DST IP', 'SRC PORT', 'DST PORT', 'TIME'])
            
            # Live Capture starts here and use try catch for any capture field exceptions
            for packet in Live_Capture.sniff_continuously():  
                try:
                    #print(packet)
                    # We cannot get mac address because the ETH Layer doesn't exist in this context 
                    csvWriter.writerow([packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport, str(math.floor(float(packet.sniff_timestamp)))])
                    f.flush()                
                except Exception as e:
                    #print(e)
                    pass

    except Exception as e :

        print("capturePackets() Error : \n MSG: ", e)

        
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

# This Function is to read the traces and preprocess it using K-Means algorithm       

def kMeansPreprocess() :

    print("3")

    try :

        Traces = pd.read_csv("capturePackets_Output.csv")

        #(Rows, Columns)
        #print(Traces.shape)
        #Count of Port and Time
        #print(pd.value_counts(Traces.iloc[:, 2:].values.ravel()))

        # This is to pass the data to KMeans model and get the output as labels
        kmeans_model = KMeans(n_clusters=2, random_state=1).fit(Traces.iloc[:, 2:])
        labels = kmeans_model.labels_

        # To view the Labels
        #print(labels)

        # To add the result to a csv
        dataFrame = pd.DataFrame(Traces)
        dataFrame["CLUSTER"] = labels
        dataFrame = dataFrame.sort_values("CLUSTER")
        dataFrame.to_csv("KMeans_Preprocess_Output.csv", index = False)

        # This is to know the count of IP on each cluster
        #print(pd.crosstab(labels, Traces['SRC IP']))

        # This is to invoke the next process
        attackSearch(labels, dataFrame)

    except Exception as e :

        print("kMeansPreprocess() Error : \n MSG: ", e)
        print("Running capturePackets() again...")
        startProcess()


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

# This Function is to process the data to find out DoS Attacks

def attackSearch(labels, dataFrame) : 

    print("4")

    try :
        Error_SRC = []
        Error_DST = []

        counter = Counter(labels)
        max_counter = max(counter)

        # To view the Counter
        #print(counter)
        #print(max(counter))

        # This is to select the packets in the large cluster
        dataFrame_Cluster = dataFrame.loc[dataFrame['CLUSTER'] == max_counter]

        # This is to sort the selected packets based on timestamp
        dataFrame_Time = dataFrame_Cluster.sort_values("TIME")
        #print(dataFrame_Time)

        # This is to get the unique time values
        counter = Counter(dataFrame_Time["TIME"])
        #print(counter)
        #print(counter.keys())

        # This is to process the packets of each time value
        for i in counter.keys() :
            dataFrame_TimeWindow = dataFrame_Time.loc[dataFrame_Time['TIME'] == i]
            #print(dataFrame_TimeWindow)

            # This is to store unique Source IP
            SRC_Array = dataFrame_TimeWindow['SRC IP'].unique()
            #print(SRC_Array)

            # This is a alternate to groupby function in pandas
            for SRC in SRC_Array :
                dataFrame_SRCWindow = dataFrame_TimeWindow.loc[dataFrame_TimeWindow['SRC IP'] == SRC]
                #print(dataFrame_SRCWindow)

                # This is to store unique Destination IP
                DST_Array = dataFrame_SRCWindow['DST IP'].unique()
                #print(SRC_Array)

                # This is a alternate to get groupby.size() in padas
                for DST in DST_Array :
                    dataFrame_DSTWindow = dataFrame_SRCWindow.loc[dataFrame_SRCWindow['DST IP'] == DST]
                    #print(dataFrame_DSTWindow)
                    #print(DST, len(dataFrame_DSTWindow))
                    
                    # This is the IF Condition to check for any Attacks
                    if(len(dataFrame_DSTWindow) >= 10) and (SRC != '127.0.0.1') :
                        if SRC in IP_ADD and DST in IP_ADD :
                            #print(SRC, DST)
                            Error_SRC.append(MAC_ADD[IP_ADD.index(SRC)])
                            Error_DST.append(MAC_ADD[IP_ADD.index(DST)])

        #print(Error_SRC, Error_DST)

        # This is to invoke the next process
        addFirewallPolicy(Error_SRC, Error_DST)       

    except Exception as e :

        print("attackSearch() Error : \n MSG: ", e)
        

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
                        
# This function is to feed the output to firewall policy of Mininet

def addFirewallPolicy(Error_SRC, Error_DST) :

    try :
        print('5')

        if len(Error_SRC) != 0 :
            with open('Firewall_Rules.csv', 'a+', newline='') as f:
                csvWriter = csv.writer(f)
                for i in range(0, len(Error_SRC)) :
                    if ''+Error_SRC[i]+' '+Error_DST[i] not in ErrorList :  
                        csvWriter.writerow([''+Error_SRC[i]+' '+Error_DST[i]])
                        f.flush()
                        ErrorList.append(''+Error_SRC[i]+' '+Error_DST[i])
                        print("Updated Attacker's IP")
                        
                    if ''+Error_DST[i]+' '+Error_SRC[i] not in ErrorList :
                        csvWriter.writerow([''+Error_DST[i]+' '+Error_SRC[i]])
                        f.flush()                        
                        ErrorList.append(''+Error_DST[i]+' '+Error_SRC[i])
                        print("Updated Attacker's IP")
            f.close()

        #This is to restart the startProcess()
        startProcess()
            
    except Exception as e :

        print("addFirewallPolicy() Error : \n MSG: ", e)
        
    
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#

# First Time Start
startProcess()
