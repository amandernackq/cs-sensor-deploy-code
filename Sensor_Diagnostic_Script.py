import os
import commands

fileObj = open("SensorDiagnostic.log", "w+")

#Get system configuration
fileObj.write("\nOperating System Information:" + "\n")
fileObj.write("------------------------------" + "\n")

#Get OS type
strMAC = commands.getoutput("sw_vers")
strLinux = commands.getoutput("uname")

def command(strCmd):

    fileObj.write(strCmd + "\n")
    strOutput = commands.getoutput(strCmd)
    fileObj.write(strOutput + "\n\n")

def cmd_execution(strCmd):
    strOutput = commands.getoutput(strCmd)
    fileObj.write(strOutput + "\n\n")

#Get proxy configuration
if strMAC.find("Mac") != -1:
    fileObj.write(strMAC + "\n\n")

    fileObj.write("System Proxy Configuration:" + "\n")
    fileObj.write("---------------------------" + "\n")
    command("scutil --proxy")

    fileObj.write("Cloud Agent Proxy Configuration:" + "\n")
    fileObj.write("--------------------------------" + "\n")
    command("echo $qualys_https_proxy")
    command("echo $http_proxy")
    command("echo $https_proxy")
    command("echo $http_port")
    command("cat /etc/qualys/cloud-agent/proxy")
    command("cat /Applications/QualysCloudAgent.app/Contents/Config/proxy")

    #Get hardware configuration
    fileObj.write("Hardware Configuration:" + "\n")
    fileObj.write("-----------------------" + "\n")
    cmd_execution("hostinfo")

    #Get memory usage
    fileObj.write("Memory Usage:" + "\n")
    fileObj.write("-------------" + "\n")
    cmd_execution("top -l 1 | head -n 10 | grep PhysMem | sed 's/, /n /g'")

elif strLinux.find("Linux") != -1:
    strOut = commands.getoutput("cat /etc/*-release")
    fileObj.write(strOut + "\n\n")

    fileObj.write("System Proxy Configuration:" + "\n")
    fileObj.write("---------------------------" + "\n")
    command("cat /etc/environment")
    command("echo $qualys_https_proxy")
    command("echo $http_proxy")
    command("echo $https_proxy")
    command("echo $https_port")

    fileObj.write("Docker Proxy Configuration:" + "\n")
    fileObj.write("---------------------------" + "\n")
    command("systemctl show --property=Environment docker")
    command("cat /etc/sysconfig/docker")
    command("cat /etc/default/docker")

    fileObj.write("Cloud Agent Proxy Configuration:" + "\n")
    fileObj.write("--------------------------------" + "\n")
    command("cat /etc/sysconfig/qualys-cloud-agent")
    command("cat /etc/default/qualys-cloud-agent")

    #Get CPU architecture information
    fileObj.write("Systems CPU architecture:" + "\n")
    fileObj.write("-------------------------" + "\n")
    cmd_execution("lscpu")

    #Get systems RAM usage
    fileObj.write("Systems RAM Usage:" + "\n")
    fileObj.write("------------------"+ "\n")
    cmd_execution("cat /proc/meminfo")

    #Get load average
    fileObj.write("Systems Load Average:" + "\n")
    fileObj.write("---------------------" + "\n")
    cmd_execution("cat /proc/loadavg")

else:
    fileObj.write("Unknown system configuration" + "\n\n")

#Get system date
fileObj.write("System Date:" + "\n")
fileObj.write("------------" + "\n")
cmd_execution("date")

#Get time since last boot
fileObj.write("Display time since last boot:" + "\n")
fileObj.write("-----------------------------" + "\n")
cmd_execution("uptime")

#Get docker version
fileObj.write("Docker version:" + "\n")
fileObj.write("---------------" + "\n")
cmd_execution("docker version")

#Get socket configuration
fileObj.write("Socket configuration:" + "\n")
fileObj.write("---------------------" + "\n")
strOutput = commands.getoutput("cat /etc/sysconfig/docker")
if strOutput.find("-H tcp://") != -1:
    fileObj.write("Docker on host is configured to communicate over TCP socket." + "\n\n")
elif os.path.exists("/var/run/docker.sock"):
    fileObj.write("A unix domain socket is available at /var/run/docker.sock on Docker host." + "\n\n")
else:
    fileObj.write("Docker socket configuration is unknown" + "\n\n")

#Get total number of docker images
strOutput = commands.getoutput("docker images -q | wc -l")
fileObj.write("Total number of docker images: " + strOutput + "\n")
fileObj.write("------------------------------" + "\n")
cmd_execution("docker images -a")

#Get total number of docker containers
strOutput = commands.getoutput("docker ps -a -q | wc -l")
fileObj.write("Total number of containers: " + strOutput + "\n")
fileObj.write("---------------------------" + "\n")
cmd_execution("docker ps -a")

#Get CPU and Memory usage
fileObj.write("CPU and Memory usage of running containers:" + "\n")
fileObj.write("-------------------------------------------" + "\n")
cmd_execution("docker stats --no-stream")

#Check if qualys-container-sensor exists else try default location of persistent storage
inspCmd = "docker inspect qualys-container-sensor"
status = commands.getstatusoutput(inspCmd)
if status[0] == 0:
    #Get persistent storage location
    strCmd = "docker inspect qualys-container-sensor | grep -e " + "/usr/local/qualys/qpa/data" + " | grep -Ev 'Destination|/usr/local/qualys/qpa/data/conf/agent-data' | cut -d ':' -f -1 | awk '{print $1'} | tr -d '" + '"' +"'"
    strStorage = commands.getoutput(strCmd)
else:
    strStorage = "/usr/local/qualys/sensor/data"
    fileObj.write("qualys-container-sensor is not present on docker host. Gathering persistent storage from default location." + "\n")

fileObj.close()

#Get docker logs of QCS
status = commands.getoutput("docker logs qualys-container-sensor --details")
with open('QCSDockerLogs.log', 'w') as fileDockerLog:
    if len(status) == 0:
        fileDockerLog.write("No docker logs available for qualys-container-sensor\n")
    else:
        fileDockerLog.write(status)

#Generate Tar Ball
tarCmd = "tar -cvf SensorDiagnostic.tar SensorDiagnostic.log QCSDockerLogs.log"
if os.path.exists(strStorage.rstrip() + "/logs") == True:
    tarCmd = tarCmd + " -C " + strStorage.rstrip() + " logs"
    if os.path.isfile(strStorage.rstrip() + "/conf/ScanInfo.json") == True:
            tarCmd = tarCmd + " -C " + strStorage.rstrip() + "/conf ScanInfo.json"
    else:
        with open('ScanInfo.json', 'w') as fileScanInfo:
            fileScanInfo.write('File Not Found\n')
            tarCmd = "tar -cvf SensorDiagnostic.tar SensorDiagnostic.log QCSDockerLogs.log ScanInfo.json" + " -C " + strStorage.rstrip() + " logs"
else:
    with open('ScanInfo.json', 'w') as fileScanInfo:
            fileScanInfo.write('File Not Found\n')
    with open('qpa.log', 'w') as fileLog:
        fileLog.write('File Not Found\n')
        tarCmd = tarCmd + " qpa.log" + " ScanInfo.json"
strOutput = commands.getoutput(tarCmd)

#CleanUp
os.system("rm -rf SensorDiagnostic.log ScanInfo.json qpa.log QCSDockerLogs.log")
