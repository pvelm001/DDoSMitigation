# This is to read captured traces

import pyshark

File_Capture = pyshark.FileCapture('./Traces/Example_Traces_1.pcapng')

File_Capture

print(File_Capture[0])
