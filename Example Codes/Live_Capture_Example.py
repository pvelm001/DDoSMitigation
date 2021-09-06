# This is to read the live traces

import pyshark

Live_Capture = pyshark.LiveCapture(interface = 'any')

for packet in Live_Capture.sniff_continuously():

    try: 
        print ('Just Arrived : ', packet)
        print ('Details Fetched : ')
        print ('Source IP : ', packet.ip.src)
        print ('Destination IP : ', packet.ip.dst)
        print ('Source MAC : ', packet.eth.src)
        print ('Destination MAC : ', packet.eth.dst)
        #need udp
        #print ('Source PORT : ', packet.udp.srcport)
        #print ('Destination PORT : ', packet.udp.dstport)
        
    except:
        pass

    
    

