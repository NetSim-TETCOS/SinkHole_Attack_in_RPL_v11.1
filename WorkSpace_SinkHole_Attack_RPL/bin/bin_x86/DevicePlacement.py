#
"""
This script is for reading sumo configuration file to get simulation time, simulation steps and other external parameters
Then it runs Sumo in CLI mode to get vehicles initial positions
"""
#	@file	 DevicePlacement.py
#	@author  Kshitij Singh
#	@date    02-07-2016
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

#Importing Libraries
import os, sys, time, subprocess

#Command Arguments passed as python DevicePlacement.py <path/sumo_config_file_name.sumo.cfg> <path/File_to_be_written_name.txt>
config_file=sys.argv[1]        							#Configuration File name
file_for_writing=sys.argv[2]							#File to be written on

print("Configuration file =", config_file)
print('')
print("File_for_writing =", file_for_writing)
print('')

B= [str(x) for x in file_for_writing.split("\\")]

C=len(B[len(B)-1])

#This will create roadsplacement file, by removing last term of path (Namely devicePlacement.txt and adding RoadsPlacement.txt (Same path reserved)
roadfile=file_for_writing[:-C]
roadfile2=file_for_writing[:-C]

roadfile = roadfile +"RoadsPlacement.txt"	#Roads placement file in same path. This will have road's coordinates multiplied by a factor

#Specify SUMO_HOME for sumo directory in Environment variables of your system
print("Sumo Directory =",os.environ['SUMO_HOME'])
SUMO_HOME = os.environ['SUMO_HOME']

#Stripping for removing \n, \0"
config_file_stripped=config_file.strip()

#Lets check whether Sumo is present or not, and then go to the tools folder of Sumo
print("Checking Sumo...")
try:
    sys.path.append(os.path.join(SUMO_HOME, "tools")) 			#go to tools folder
    from sumolib import checkBinary								#A sumo back-end library to check if sumo is present or not
except ImportError:
    sys.exit("Please declare environment variable 'SUMO_HOME' as the root directory of your sumo installation (it should contain folders 'bin', 'tools' and 'docs')")

# Specify a Port for TCP connection. Python will interact with Sumo on this port. Make sure no other application is using this port
PORT = 8813

sumoBinary = checkBinary('sumo')

#Open Sumo on the specified port. It is opened in parallel to python program, with standard-in and standard-out for connections
sumoProcess = subprocess.Popen([sumoBinary,  "-c", config_file,'--start','--remote-port', str(PORT)], stdout=sys.stdout, stderr=sys.stderr)

#open the file for writing specified in argument
print("File to be written ",file_for_writing)
fw = open(file_for_writing, 'w')
froads = open(roadfile,'w')

#Import Sumo backend libraries for TCP connection
import traci, string
import traci.constants as tc

""
#Initiate connection on Specified Port
print("Initiating port...")
traci.init(PORT)

# write #Device Placement File in file_to_be_written
fw.write("#Device Placement File\n")

#Get the Boundary of Sumo Simulation. This would be used in Netsim to specify Environment
r=traci.simulation.getNetBoundary()

# write Env length =  in file_to_be_written
fw.write("Env length = ")
greater_coordinate=(r[1][1] if r[1][1]>r[1][0] else r[1][0])
fw.write(str(greater_coordinate))	 # Check if Length is bigger or breadth. Larger is written (Square shaped boundary in Netsim)
fw.write('\n')	# Next line

file=config_file
config_read = open(file, 'r')   #Open the sumo Config file
k=0
config_file_r="c"

print("Reading file...")

while (config_file_r):
	config_file_r=config_read.readline()  #read the config file line by line
	if config_file_r.find("step")>0:	  #if you find step, stop
		break


print("Writing Simulation Steps:")

A=config_file_r.strip()				#Remove \n \0 \t characters
B = [str(x) for x in A.split('"')]	#Split on double quotes ""
fw.write("Step = ")					#Write "Step =" in the file
fw.write(B[1])						#Write the Simulation Step value
fw.write('\n')						#Next line

config_read = open(file, 'r')		#Again open the file

print("Reading file again")

k=0
config_file_r="c"
while (config_file_r):
	config_file_r=config_read.readline()	#Read File line by line
	#print config_file
	#time.sleep(1)
	if config_file_r.find("end")>0:			#Exit on finding end

		break
print("Writing Simulation time")

A=config_file_r.strip()				#Remove \n \0 \t characters
B2 = [str(x) for x in A.split('"')]	#Split on double quotes ""
fw.write("Simulation time = ")		#Write "Simulation time =" in the file
fw.write(B2[1])						#Write the Simulation time value
fw.write('\n')						#Next line

	#	break

vehicle_pos=''						#This variable is the string. It works on the principal that it will Concatenate for each vehicles starting position
departed_no=0						#This variable adds up on finding a vehicle that depart at each point of sumo time
#time.sleep(5.0)
step = 0							#Simulation step counter
l=1

curr_list=''

factor=400*2.74/greater_coordinate


print("Running Simulation...")
while step < float(B2[1]):			#As long as it is less than Simulation time
   #time.sleep(1.0)
	traci.simulationStep()			#Proceed a Simulation step in Sumo
	curr_departed_list=traci.simulation.getDepartedIDList()		#List of Vehicles departed in this simulation step
	curr_departed_no=traci.simulation.getDepartedNumber()		#No. of vehicles departed in rthis simulation step
	departed_no=departed_no+curr_departed_no					#Add it in the Total vehicles departed

	#Lets get the positions of vehicles departed in this simulation step
	for i in curr_departed_list:
		#print str(l)+" "+  str(i) +" " + "(" +  str(abs(traci.vehicle.getPosition(i)[0])) + ", " + str(abs(traci.vehicle.getPosition(i)[1])) + ")"+"\n"
		vehicle_pos=vehicle_pos+ str(l)+" "+  str(i) +" " + "(" +  str(abs(traci.vehicle.getPosition(i)[0])) + ", " + str(abs(traci.vehicle.getPosition(i)[1])) + ")"
		vehicle_pos=vehicle_pos+'\n'
		l=l+1

	step += float(B[1])			#Counter increase
	#time.sleep(1)

#Write road positions in file
print ("Getting edges\n")
edge=traci.lane.getIDList()
roadpos=''
i=0
#Loop for each edge
for j in edge:
	if j[0] != ':':
		i=i+1
#		roadpos=roadpos+str(i)+' '+'('+ str (abs(traci.lane.getShape(j)[0][0])*factor+88) +','+ str(abs(traci.lane.getShape(j)[0][1])*factor+88)+ ',' + str(abs(traci.lane.getShape(j)[1][0])*factor+88)+ ',' + str(abs(traci.lane.getShape(j)[1][1])*factor+88)+') \n'
		roadpos=roadpos+str(i)+' '+'('+ str (abs(traci.lane.getShape(j)[0][0])) +','+ str(abs(traci.lane.getShape(j)[0][1]))+ ',' + str(abs(traci.lane.getShape(j)[1][0]))+ ',' + str(abs(traci.lane.getShape(j)[1][1]))+') \n'

print ("Getting vertices\n")

junc=traci.junction.getIDList()
vertices=''
i=0
for j in junc:
	if j[0] != ':':
		#print j
		i=i+1
		vertices=vertices+str(i)+' '+ str (traci.junction.getShape(j)) +' \n'

print("Writing file Ending part")

#curr_junctions=traci.junction.getIDList()	#Junctions present currently
fw.write("Number of device placed = ")		#Write "Number of device placed = "
fw.write(str(departed_no))					#Write the number of vehicles, Which is same as total vehicles departed
fw.write('\n')								#New line
fw.write("#Device_Number (X-Pos, Y-Pos)")	#Write "#Device_Number (X-Pos, Y-Pos)"
fw.write("\n")								#New line
fw.write(vehicle_pos)						#Write Vehicle positions
froads.write("#RoadsPlacement\n")			#Write Road positions
froads.write(roadpos)
#froads.write("#Vertices\n")
#froads.write(lkk)
froads.write("#Vertices\n")
froads.write(vertices)


print("Closing Connection")
traci.close()								#Close TCP Connection
print("Sumo closed")
print("Python is exiting")
fw.close()									#close files
froads.close()

config_read.close()
