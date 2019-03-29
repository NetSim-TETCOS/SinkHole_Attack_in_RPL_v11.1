#
"""
This script is for Establishing pipes connection with Netsim backend after Play button of Netsim is pressed. The Pipes connection is made
by Sumo-Interface file of Netsim Back end. After pipes connection, Dynamically, This file reads Vehicle coordinates from sumo and passes
to Netsim. Based on certain algorithms, Netsim can bring alterations in sumo dynamically. This file also has an optional GUI
(under development) which can Traces movements from Sumo and Packets from Netsim.
"""
#	@file	 SumoRun.py
#	@author  Kshitij Singh
#	@date    07-07-2016
#	@update  Kundrapu Dilip Kumar
#   @data    16-02-2019
#   @version 11.1.8 (Python 3.7)
"""
This file is a part of Netsim code. It uses libraries to establish TCP connection between Sumo and python, and get/modify data dynamically
Sumo is a free software, however Netsim is a commercial software. Users are not advised to modify the code, however they can use this code
to learn about the Sumo libraries, basic file reading/writing operations in python etc.
"""

#Common Libraries
#	<os>
"""
This module provides a portable way of using operating system dependent functionality. If you just want to read or write a file see open(),
if you want to manipulate paths, see the os.path module, and if you want to read all the lines in all the files on the command line see the file input
module. For creating temporary files and directories see the temp file module, and for high-level file and directory handling see the shutil module.
"""

#	<sys>
"""
This module provides access to some variables used or maintained by the interpreter and to functions that interact strongly with the interpreter.
 It is always available
"""

#	<time>
"""
This module provides various time-related functions. For related functionality, see also the date time and calendar modules.
Although this module is always available, not all functions are available on all platforms. Most of the functions defined in this module call platform C library
functions with the same name. It may sometimes be helpful to consult the platform documentation, because the semantics of these functions varies among platforms.
"""

#	<subprocess>
"""
The subprocess module allows you to spawn new processes, connect to their input/output/error pipes, and obtain their return codes. This module intends to replace
several older modules and functions:
"""

#   <win32file>  <win32pipe>
"""
Staying within the Windows interprocess communication mechanisms, we had positive experience using windows named pipes. Using Windows overlapped IO and the
win32pipe module from pywin32.You can learn much about win32 and python in the Python Programming On Win32 book.
"""

#   <Tkinker>
"""
Tkinter is the standard GUI library for Python. Python when combined with Tkinter provides a fast and easy way to create GUI applications. Tkinter provides
a powerful object-oriented interface to the Tk GUI toolkit.
Creating a GUI application using Tkinter is an easy task. All you need to do is perform the following steps
Import the Tkinter module.
Create the GUI application main window.
Add one or more of the above-mentioned widgets to the GUI application.
Enter the main event loop to take action against each event triggered by the user.
"""

#Importing Libraries
import os, sys, win32pipe, win32file, subprocess, time

#Command Arguments passed as python combined3.py <path/sumo_config_file_name.sumo.cfg>
config_file=sys.argv[1]   #Configuration File name
print(config_file)

#Specify SUMO_HOME for sumo directory in Environment variables of your system
print("Sumo Directory =",os.environ['SUMO_HOME'])
SUMO_HOME = os.environ['SUMO_HOME']

gui='0'

#Make the Pipe Connections
#Define the pipe
p1 = win32pipe.CreateNamedPipe(r'\\.\pipe\netsim_sumo_pipe',
    win32pipe.PIPE_ACCESS_DUPLEX,
    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
    1, 65536, 65536,300,None)

print("Waiting for netsim to connect...")
#Connect the Pipe
win32pipe.ConnectNamedPipe(p1, None)

#Read once
data = win32file.ReadFile(p1, 4096)  #Get whether GUI =1 or 0 from Netsim
gui=data[1][0]

#The value of 'gui' is read from: data = win32file.ReadFile(p1,4096)
#In Pyton-3, the value of 'gui' is an ASCII of the string char(48 for '0') i.e., an int type, whereas in Python-2 the value of 'gui' is directly of str type.
# So we are converting the ASCII to char only if it is of int type ---> We are using 'if' to also make the code compatable with Python-2
if isinstance(gui, int):
    gui = chr(gui)

#Lets check whether Sumo is present or not, and then go to the tools folder of Sumo
print("Checking Sumo...")
try:
    sys.path.append(os.path.join(SUMO_HOME, "tools")) 					#go to tools folder
    from sumolib import checkBinary										#A sumo back-end library to check if sumo is present or not
except ImportError:
    sys.exit("Please declare environment variable 'SUMO_HOME' as the root directory of your sumo installation (it should contain folders 'bin', 'tools' and 'docs')")

# Specify a Port for TCP connection. Python will interact with Sumo on this port. Make sure no other application is using this port
print("Starting Sumo Simulation")
PORT = 8813

if gui=='1':
	sumoBinary = checkBinary('sumo-gui')		#Open SUMO in GUI
else:
	sumoBinary = checkBinary('sumo')			#Open SUMO in CLI

sumoProcess = subprocess.Popen([sumoBinary, "-c", config_file,'--start','--remote-port', str(PORT)], stdout=sys.stdout, stderr=sys.stderr)


# Import Sumo Libraries
import traci, string
import traci.constants as tc

traci.init(PORT)

print(" Running Sumo Simulation...")

step = 0
while step < 100000:
	garbage= "hello".encode()				#Send Garbage
	win32file.WriteFile(p1, garbage)

	jk =win32file.ReadFile(p1, 4096)	#Read vehicle from Netsim

	vehicle_from_Netsim=jk[1].lower()[:-1]	#convert to lower case
	vehicle_from_Netsim = vehicle_from_Netsim.decode("utf-8")

	k=0									#Flag if vehicle found
	k5=traci.vehicle.getIDList()

	if len(k5)==0:						#No vehicle present, let the simulation continue
		traci.simulationStep()

	for i in k5:
		if i.lower() == vehicle_from_Netsim:		#If vehicle found in sumo
			k=1										#Turn on flag
			break;

	if k==1:
		if i == k5[0]:							#For every 1st vehicle present in list of vehicles, simulate
			traci.simulationStep()

		win32file.WriteFile(p1, 'c'.encode())			#The vehicle was found, being sent to Netsim for Connection('c' for confirmation)

        #get coordinates
		position_x = str(abs(traci.vehicle.getPosition(i)[0]))
		position_y= str(abs(traci.vehicle.getPosition(i)[1]))
		#print position_x,position_y,'\n'

        #send to Netsim
		win32file.WriteFile(p1, position_x.encode())
		win32file.WriteFile(p1, position_y.encode())
		#time.sleep(0.5)

	else :
		win32file.WriteFile(p1, 'f'.encode())				#Send not found to Netsim ('f' for denial of connection)

	step += 10

traci.close()
p1.close()
