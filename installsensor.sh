#!/bin/bash

#
# This is bash script to launch qualys sensor for docker security.
# This script runs on docker host and launches the sensor.
#

qcs_Name="qualys-container-sensor"
QCS_Name="Qualys-Container-Sensor"
Sensor_Image="qualys/sensor"
Sensor_Name=""
ConcurrentScan_value="4"
# Variable MaxConcurrentScan_value should match with
# const int8_t MAX_SCAN_THRDPOOL_SZ = 20; of file qpa/src/Constants.cpp
MaxConcurrentScan_value="20"
UseDefaults_value="false"
HostIdSearchDir_value="/etc/qualys"
EnableAutoUpdate_value="--enable-auto-update"
EnableDebugLogsOnConsole_value=""
RegistryScan_value=""
CICDDeployedSensor_value=""
LogLevel_Info=""
ImageFileFileName=""
Min_Major_Ver="1"
Min_Minor_Ver="12"
SeLinux_Opt=""
Docker_Edition=""
SeLinux_Status=""
Qualys_Https_Proxy=""
Qualys_Https_Proxy_Info=""
Qualys_Proxy_Cert_File=""
Qualys_Proxy_Cert_File_Info=""
Docker_Sock_File=""
Docker_Sock_File_Default="docker.sock"
DockerSocketDirectory_value="/var/run"
DockerSocketDirectoryPathSet="false"
Dockerd_TCP=""
Dockerd_TCP_Default="n"
Dockerd_TCP_Socket_Env=""
Dockerd_TCP_Arg=""
Docker_Arg=""
Docker="docker "
CpuLimit_CpuQuota_Kernel_Support=false
CpuUsageLimit_value="20" # Default CPU usage limit value is 20% of overall CPU available
CpuUsageLimit_defined="0"
Use_Cpus_Option="false"
Number_Of_Cpu_Cores_OnHost="1"
Cpu_Limit_Option_String=""
InputConcurrentContScan="0"
InputConcurrentImageScan="0"
RunSensorWithoutPersistentStorage="false" # --sensor-without-persistent-storage
HostIdSearchDirProvided="false"
RunSensorInReadOnlyMode="false" # --read-only
SensorInReadOnlyMode_value=""

usage()
{
    echo "Usage:"
    echo "installsensor.sh --help or -h <To print help message>"
    echo "installsensor.sh ActivationId=\"xxxx-xx-xxxxxxx\" CustomerId=\"xxxx-xx-xxxxxxx\" (MANDATORY)"
    echo "installsensor.sh Storage=<Directory>"
    echo "installsensor.sh ImageFile=<CompressedDockerImageFile>"
    echo "installsensor.sh LogLevel=<a number between 0 and 5>"
    echo "installsensor.sh HostIdSearchDir=<Qualys Scanner hostid file directory>"
    echo "installsensor.sh ConcurrentScan=<Number of docker/registry assets scans to run in parallel>"
    echo "installsensor.sh CpuUsageLimit=<CPU usage limit in percentage for sensor>"
    echo "installsensor.sh Proxy=<<IP/IPv6 address or FQDN>:<Port#>> ProxyCertFile=<Proxy certificate file path if proxy use any certificate>"
    echo "installsensor.sh DockerHost=<<IPv4 address or FQDN>:<Port#>> <Address on which docker daemon is configured to listen>"
    echo "installsensor.sh DockerSocketDirectory=<Docker socket directory path>"
    echo "installsensor.sh --silent or -s <Optional parameter to run script in non-interactive mode>"
    echo "installsensor.sh --disable-auto-update or -D <Do not let sensor update itself automatically>"
    echo "installsensor.sh --registry-sensor or -r <Run sensor to list and scan registry assets>"
    echo "installsensor.sh --cicd-deployed-sensor or -c <Parameter should be passed when Sensor deployed in CI/CD environment>"
    echo "installsensor.sh --enable-console-logs <Parameter should be passed when logs needs to be printed on console those can be retrieved using "docker logs" command>"
    echo "installsensor.sh --sensor-without-persistent-storage <Parameter should be passed when sensor is to be run without mapping persistent storage on host>"
    echo "installsensor.sh --read-only <Parameter should be passed when sensor is to be run in read-only mode>"
}

print_usage_and_exit()
{
    usage
    if [[ $# -lt 1 ]]; then
        exit 1
    else 
        exit $1
    fi
}

get_key()
{
    echo $1|awk -F= '{printf $1}'
}
get_val()
{
    echo $1|awk -F= '{printf $2}'
}

validate()
{
    if [[ $# -lt 1 ]]; then
        echo "Missing parameter to validate"
        return 255;
    fi
    key=$(get_key "$*")
    val=$(get_val "$*")
    if [[ "$key" != "ActivationId" &&
          "$key" != "CustomerId" &&
          "$key" != "Storage" &&
          "$key" != "ImageFile" &&
          "$key" != "ConcurrentScan" &&
          "$key" != "CpuUsageLimit" &&
          "$key" != "LogLevel" &&
          "$key" != "Proxy" &&
          "$key" != "ProxyCertFile" &&
          "$key" != "DockerHost" &&
          "$key" != "DockerSocketDirectory" &&
          "$key" != "HostIdSearchDir" ]]; then
            echo "Error: Invalid key name in $1"
            return 255
    fi
    if [[ -z "$key" || -z "$val" ]]; then
          echo "Error: Key or Value missing in [$1]"
          return 255;
    fi
    return 0
}

validate_dockerd_socket()
{
    # if $Dockerd_TCP does not have ":<port#>", add default 2375 - Will have to modify later to accomodate 2376 for TCP TLS  
    port_num="$(echo $Dockerd_TCP | awk -F':' '{print $2}')"
    if [[ -z $port_num ]]; then
        port_num="2375"
        Dockerd_TCP=$(echo $Dockerd_TCP":"$port_num)
   fi
}

set_docker_socket_file()
{
  Docker_Sock_File="$DockerSocketDirectory_value/$Docker_Sock_File_Default"
}

set_dockerd_host()
{
    if [[ $# -ne 1 ]]; then
        echo "Invalid TCP details for docker daemon."
        exit 1;
    fi

    if [ -e $Docker_Sock_File ]; then
        return
    fi
    
    Dockerd_TCP_Socket_Env="-e DOCKER_HOST=${1}"
    Docker_Arg=" -H ${1} "
    Docker="${Docker} ${Docker_Arg}"
}

check_dockerd_socket()
{
    # check if /var/run/docker.sock is present, if yes then it is preferred over tcp details provided by customer
    if [ -e ${Docker_Sock_File} ]; then
        return;
    fi

    # Check if the user provided Docker socket directory is wrong
    if [ "$DockerSocketDirectoryPathSet" == "true" ] && [ ! -e ${Docker_Sock_File} ]; then
       echo "The Docker socket file is not present in directory '$DockerSocketDirectory_value', Please provide correct Docker socket directory path."
       exit 1
    fi
    
    # check if DOCKER_HOST environment variable is set by customer or not
    # if yes then set Dockerd_TCP with that
    if [ ! -z ${DOCKER_HOST} ]; then
        Dockerd_TCP=${DOCKER_HOST}
    fi

    if [ ! -z $Dockerd_TCP ]; then
        validate_dockerd_socket
        set_dockerd_host $Dockerd_TCP
        return;
    fi

    if [ "$UseDefaults_value" == "false" ]; then
        read -e -p "Docker daemon is not listening on unix domain socket. Is docker daemon configured to listen on TCP socket? [y/N]: " Dockerd_TCP_Proceed
    elif [ "$UseDefaults_value" == "true" ]; then
        echo "Docker daemon is not listening on unix domain socket. Is docker daemon configured to listen on TCP socket?"
        exit 1
    fi

    Dockerd_TCP_Proceed="${Dockerd_TCP_Proceed:=${Dockerd_TCP_Default}}"

    if [[ "${Dockerd_TCP_Proceed}" == "y" || "${Dockerd_TCP_Proceed}" == "Y" ]] ; then
        read -e -p "Enter details of TCP socket that docker daemon is listening on [<IP/IPv6 addr Or FQDN>:<Port#>]: " Dockerd_TCP;
        if [[ -z $Dockerd_TCP ]]; then
            read -e -p "Enter valid TCP socket [<IP/IPv6 addr Or FQDN>:<Port#>]: " Dockerd_TCP;
            if [[ -z $Dockerd_TCP ]]; then
                read -e -p "Enter valid TCP socket [<IP/IPv6 addr Or FQDN>:<Port#>]: " Dockerd_TCP;
            fi
        fi
        echo ""
        if [[ -z $Dockerd_TCP ]]; then
            echo "Invalid TCP details for docker daemon"
            exit 1
        fi
        
        validate_dockerd_socket 
        set_dockerd_host $Dockerd_TCP
    fi
}


validate_docker_version()
{
# Validate docker client version
    Docker_Client_Major_Ver="$(${Docker} version -f '{{.Client.Version}}' 2>/dev/null | awk -F'.' '{print $1}')"
    Docker_Client_Minor_Ver="$(${Docker} version -f '{{.Client.Version}}' 2>/dev/null | awk -F'.' '{print $2}')"
    
    if [ -z "$Docker_Client_Major_Ver" ]; then
        echo "Cannot connect to the Docker client. Is the docker client installed on this host?"
        exit 1
    fi
    if [[ $Docker_Client_Major_Ver -lt $Min_Major_Ver ]]; then
        echo "Minimum docker client version($Min_Major_Ver.$Min_Minor_Ver.0) requirement failed."
        exit 1
    elif [[ $Docker_Client_Major_Ver -eq $Min_Major_Ver && $Docker_Client_Minor_Ver -lt $Min_Minor_Ver ]]; then
        echo "Minimum docker client version($Min_Major_Ver.$Min_Minor_Ver.0) requirement failed."
        exit 1
    fi
# Validate docker server version
    Docker_Server_Major_Ver="$(${Docker} version -f '{{.Server.Version}}' 2>/dev/null | awk -F'.' '{print $1}')"
    Docker_Server_Minor_Ver="$(${Docker} version -f '{{.Server.Version}}' 2>/dev/null | awk -F'.' '{print $2}')"

    if [ -z "$Docker_Server_Major_Ver" ]; then
        echo "Cannot connect to the Docker daemon. Is the docker daemon running on this host?"
        exit 1
    fi
    if [[ $Docker_Server_Major_Ver -lt $Min_Major_Ver ]]; then
        echo "Minimum docker server version($Min_Major_Ver.$Min_Minor_Ver.0) requirement failed."
        exit 1
    elif [[ $Docker_Server_Major_Ver -eq $Min_Major_Ver && $Docker_Server_Minor_Ver -lt $Min_Minor_Ver ]]; then
        echo "Minimum docker server version($Min_Major_Ver.$Min_Minor_Ver.0) requirement failed."
        exit 1
    fi
}

validate_ssl_certificate()
{
    if [[ $# -ne 1 ]]; then
        echo "Invalid proxy certificate file path."
        exit 1;
    fi

    if [[ -f "$1" ]]; then
        Begin_Cert_Str="$(grep 'BEGIN CERTIFICATE' ${1})"
        End_Cert_Str="$(grep 'END CERTIFICATE' ${1})"
        if [[ -z "$Begin_Cert_Str" || -z "$End_Cert_Str" ]]; then
            echo "Invalid proxy certificate file."
            exit 1
        fi
    else
        echo "Invalid proxy certificate file path."
        exit 1
    fi
}

linux_use_proxy()
{
    Proxy_Default="y"
    Cert_Default="y"
    if [[ $# -ne 2 ]]; then
        echo "missing parameter to linux_use_proxy"
        return 255;
    fi

    if [[ -f $1 ]]; then
        Qualys_Https_Proxy="$(cat ${1} | grep "^[[:space:]]*${2}" | awk -F'=' '{print $2}')"
        if [[ ! -z "$Qualys_Https_Proxy" ]]; then
            read -e -p "Is this the proxy: $Qualys_Https_Proxy [Y/n]: " Proxy_Proceed
            Proxy_Proceed="${Proxy_Proceed:=${Proxy_Default}}"
            if [[ "${Proxy_Proceed}" == "y" || "${Proxy_Proceed}" == "Y" ]] ; then
                Qualys_Https_Proxy_Info="-e qualys_https_proxy=${Qualys_Https_Proxy}"
                read -e -p "Is there a certificate for proxy '$Qualys_Https_Proxy' [Y/n]: " Cert_Proceed
                Cert_Proceed="${Cert_Proceed:=${Cert_Default}}"
                if [[ "${Cert_Proceed}" == "y" || "${Cert_Proceed}" == "Y" ]] ; then
                    if [[ -f /etc/qualys/qpa/cert/custom-ca.crt ]]; then
                        read -e -p "Do you want to use /etc/qualys/qpa/cert/custom-ca.crt ceritificate [Y/n]: " Cert_Proceed1
                        Cert_Proceed1="${Cert_Proceed1:=${Cert_Default}}"
                        if [[ "${Cert_Proceed1}" == "y" || "${Cert_Proceed1}" == "Y" ]] ; then
                            validate_ssl_certificate /etc/qualys/qpa/cert/custom-ca.crt
                            Qualys_Proxy_Cert_File_Info="-v /etc/qualys/qpa/cert/custom-ca.crt:/etc/qualys/qpa/cert/custom-ca.crt"
                        fi
                    fi
                    if [[ -z "$Qualys_Proxy_Cert_File_Info" && -f /etc/qualys/cloud-agent/cert/custom-ca.crt ]]; then
                        read -e -p "Do you want to use /etc/qualys/cloud-agent/cert/custom-ca.crt ceritificate [Y/n]: " Cert_Proceed2
                        Cert_Proceed2="${Cert_Proceed2:=${Cert_Default}}"
                        if [[ "${Cert_Proceed2}" == "y" || "${Cert_Proceed2}" == "Y" ]] ; then
                            validate_ssl_certificate /etc/qualys/cloud-agent/cert/custom-ca.crt
                            Qualys_Proxy_Cert_File_Info="-v /etc/qualys/cloud-agent/cert/custom-ca.crt:/etc/qualys/qpa/cert/custom-ca.crt"
                        fi
                    fi
                    if [[ -z "$Qualys_Proxy_Cert_File_Info" ]]; then
                        read -e -p "Enter https proxy certificate file path: " Proxy_File_Path;
                        if [[ -z $Proxy_File_Path ]]; then
                            read -e -p "Enter valid https proxy certificate file path: " Proxy_File_Path;
                            if [[ -z $Proxy_File_Path ]]; then
                                read -e -p "Enter valid https proxy certificate file path: " Proxy_File_Path;
                            fi
                        fi
                        validate_ssl_certificate $Proxy_File_Path
                        if [[ ! "$Proxy_File_Path" =~ ^/ ]]; then
                            Proxy_File_Path="$PWD/$Proxy_File_Path"
                        fi
                        Qualys_Proxy_Cert_File_Info="-v ${Proxy_File_Path}:/etc/qualys/qpa/cert/custom-ca.crt"
                    fi
                fi
            fi
        fi
    fi
}
macos_use_proxy()
{
    Proxy_Default="y"
    Cert_Default="y"
    if [[ $# -ne 2 ]]; then
        echo "missing parameter to linux_use_proxy"
        return 255;
    fi

    if [[ -f $1 ]]; then
        Qualys_Https_Proxy="$(cat ${1} | grep "^[[:space:]]*${2}" | awk -F'=' '{print $2}')"
        if [[ ! -z "$Qualys_Https_Proxy" ]]; then
            read -e -p "Is this the proxy: $Qualys_Https_Proxy [Y/n]: " Proxy_Proceed
            Proxy_Proceed="${Proxy_Proceed:=${Proxy_Default}}"
            if [[ "${Proxy_Proceed}" == "y" || "${Proxy_Proceed}" == "Y" ]] ; then
                Qualys_Https_Proxy_Info="-e qualys_https_proxy=${Qualys_Https_Proxy}"
                read -e -p "Is there a certificate for proxy '$Qualys_Https_Proxy' [Y/n]: " Cert_Proceed
                Cert_Proceed="${Cert_Proceed:=${Cert_Default}}"
                if [[ "${Cert_Proceed}" == "y" || "${Cert_Proceed}" == "Y" ]] ; then
                    if [[ -f /Applications/QualysCloudAgent.app/Contents/Config/cert/custom-ca.crt ]]; then
                        read -e -p "Do you want to use /Applications/QualysCloudAgent.app/Contents/Config/cert/custom-ca.crt ceritificate [Y/n]: " Cert_Proceed1
                        Cert_Proceed1="${Cert_Proceed1:=${Cert_Default}}"
                        if [[ "${Cert_Proceed1}" == "y" || "${Cert_Proceed1}" == "Y" ]] ; then
                            validate_ssl_certificate /etc/qualys/qpa/cert/custom-ca.crt
                            Qualys_Proxy_Cert_File_Info="-v /Applications/QualysCloudAgent.app/Contents/Config/cert/custom-ca.crt:/etc/qualys/qpa/cert/custom-ca.crt"
                        fi
                    fi
                    if [[ -z "$Qualys_Proxy_Cert_File_Info" ]]; then
                        read -e -p "Enter https proxy certificate file path: " Proxy_File_Path;
                        if [[ -z $Proxy_File_Path ]]; then
                            read -e -p "Enter valid https proxy certificate file path: " Proxy_File_Path;
                            if [[ -z $Proxy_File_Path ]]; then
                                read -e -p "Enter valid https proxy certificate file path: " Proxy_File_Path;
                            fi
                        fi
                        validate_ssl_certificate $Proxy_File_Path
                        if [[ ! "$Proxy_File_Path" =~ ^/ ]]; then
                            Proxy_File_Path="$PWD/$Proxy_File_Path"
                        fi
                        Qualys_Proxy_Cert_File_Info="-v ${Proxy_File_Path}:/etc/qualys/qpa/cert/custom-ca.crt"
                    fi
                fi
            fi
        fi
    fi
}

check_kernel_support_for_cpu_limit_quota()
{

  # First check if the docker info -f command is supported, it is not supported
  # on 1.12 and maybe the case for some other immediate version
  # If not, then check presence of files cpu.cfs_period_us and cpu.cfs_quota_us
  # in /sys/fs/cgroup/cpu,cpuacct/ 

    if docker ${Dockerd_TCP_Arg} info -f '{{.CPUCfsPeriod}}' 1> /dev/null 2>&1; then
      CPUCfsPeriod=false
      CPUCfsQuota=false

      CPUCfsPeriod=$(docker ${Dockerd_TCP_Arg} info -f '{{.CPUCfsPeriod}}')
      CPUCfsQuota=$(docker ${Dockerd_TCP_Arg} info -f '{{.CPUCfsQuota}}')

      # If both are true then allow cpu limit and cpu quota option
      if [[ "$CPUCfsPeriod" = true && "$CPUCfsQuota" = true ]] ; then
        CpuLimit_CpuQuota_Kernel_Support=true
      else
        CpuLimit_CpuQuota_Kernel_Support=false
      fi
    else
      #Check in file
      if ls /sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota* 1> /dev/null 2>&1; then
        if ls /sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period* 1> /dev/null 2>&1; then
          CpuLimit_CpuQuota_Kernel_Support=true
        else
          CpuLimit_CpuQuota_Kernel_Support=false
        fi
      else
        CpuLimit_CpuQuota_Kernel_Support=false
      fi
    fi
}

check_cpu_limit_option()
{
    Docker_Client_Major_Ver="$(docker ${Dockerd_TCP_Arg} version -f '{{.Client.Version}}' 2>/dev/null | awk -F'.' '{print $1}')"
    Docker_Client_Minor_Ver="$(docker ${Dockerd_TCP_Arg} version -f '{{.Client.Version}}' 2>/dev/null | awk -F'.' '{print $2}')"

    if [ $Docker_Client_Major_Ver -gt 1 ]
    then
      Use_Cpus_Option=true
    elif [ $Docker_Client_Major_Ver -eq 1 ]
    then
      if [ "$Docker_Client_Minor_Ver" -gt 12 ]
      then
        Use_Cpus_Option=true
      fi
   fi
}

get_number_of_cpu_cores()
{
  if [ -e /proc/cpuinfo ]; then
    Number_Of_Cpu_Cores_OnHost="$(cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l)"
  else
    CpuCount="$(sysctl -n hw.ncpu)"
    if ! [[ "$CpuCount" =~ $integer_reg ]] ; then
       echo "Info: Using default value 1 for available number of cpu core."
    else
       Number_Of_Cpu_Cores_OnHost="$CpuCount"
    fi
  fi
}

build_cpu_limit_option_string()
{
  if [ "$Use_Cpus_Option" == "true" ]
  then
    # convert CPU limit percentage in the form of value that can be set for "--cpus" option
    cpuUsage=$(echo $(($CpuUsageLimit_value)) | awk '{print $1 / 100 } ')
    cpuUsageLimit=$(echo $cpuUsage $Number_Of_Cpu_Cores_OnHost | awk '{print $1 * $2}')
    Cpu_Limit_Option_String=" --cpus $cpuUsageLimit"
  else
    cpuUsageLimit=$(expr $(expr $CpuUsageLimit_value \* 1000) \* $Number_Of_Cpu_Cores_OnHost)
    Cpu_Limit_Option_String=" --cpu-period 100000 --cpu-quota $cpuUsageLimit"
  fi
}
 
handle_cpu_usage_option()
{
    # Check if the kernel supports cpu period and cpu quota specification. 
    # If yes, continue. Provide option to sensor if value is non-zero
    # If no, continue if user has not provided any value for cpu usage
    # Exit with error if user has provided non-zero value for cpu usage and
    # kernel does not support the specification

    check_kernel_support_for_cpu_limit_quota
    
    if [ "$CpuLimit_CpuQuota_Kernel_Support" = true  ]; then 
        if [ $CpuUsageLimit_value -ne 0 ]; then
            check_cpu_limit_option
            get_number_of_cpu_cores
            build_cpu_limit_option_string
        else
            echo "Value 0 for CpuUsageLimit implies that Sensor container will not have CPU usage limit."
        fi
    else
        if [ $CpuUsageLimit_defined -eq 0 ]; then
            echo "Kernel does not support limiting CPU usage for a container. Sensor container will have no such limit."
        else
            if [ $CpuUsageLimit_value -eq 0 ]; then
                echo "Kernel does not support limiting CPU usage for a container. Sensor container will have no such limit."
            else
                echo "Kernel does not support limiting CPU usage for a container. Update Kernel or do not provide CpuUsageLimit. Exiting!"
                exit 1
            fi
        fi
    fi
}

[ -d /etc/qualys ] || mkdir -p /etc/qualys

#if [ ! -d /etc/qualys ]; then
#    sudo mkdir -p /etc/qualys
#fi

Initial_Directory_Name="$(echo "$0" | awk -F'installsensor.sh' '{print $1}')"

if [[ $# -lt 3 ]]; then
  echo "Insufficient arguments."
  echo "ActivationId and CustomerId are mandatory."
  echo "Storage or --sensor-without-persistent-storage must be specified."
  echo ""
  print_usage_and_exit 0
fi

#regex for validation checks
id_reg="^([A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12})"
dockerid_reg1="^([A-Za-z0-9]{12})"
dockerid_reg2="^([A-Za-z0-9]{64})"
ImageFile_req="*.tar"
integer_reg='^([0-9]+$)'

myArray=()
index=0
whitespace="[[:space:]]"
for i in "$@"
do
    if [[ $i =~ $whitespace ]]
    then
        i=\"$i\"
    fi

    if [[ $i == "--help" || $i == "-h" ]]; then
        print_usage_and_exit

    elif [[ $i == "--silent" || $i == "-s" ]]; then
        UseDefaults_value="true"
    
    elif [[ $i == "--disable-auto-update" || $i == "-D" ]]; then
        EnableAutoUpdate_value=""

    elif [[ $i == "--registry-sensor" || $i == "-r" ]]; then
        RegistryScan_value="--registry-sensor"

    elif [[ $i == "--cicd-deployed-sensor" || $i == "-c" ]]; then
        CICDDeployedSensor_value="--cicd-deployed-sensor"

    elif [[ $i == "--enable-console-logs" ]]; then
        EnableDebugLogsOnConsole_value="--enable-console-logs"
    
    elif [[ $i == "--sensor-without-persistent-storage" ]]; then
        RunSensorWithoutPersistentStorage="true"
        SensorWithoutPersistentStorage_value="--sensor-without-persistent-storage"

    elif [[ $i == "--read-only" ]]; then
        RunSensorInReadOnlyMode="true"
        SensorInReadOnlyMode_value="--read-only"

    else
        myArray[$index]="$i"
        index=$(( $index + 1 ))
    fi
done

# If values are provided for both cicd sensor and registry sensor, then exit
if [[ ! -z $RegistryScan_value && ! -z $CICDDeployedSensor_value ]]; then
  echo "Registry scanning in CI/CD mode not supported. Exiting!"
  exit 1
fi

# If values are provided for both sensor without persistent storage and read only, then exit
if [[ "$RunSensorWithoutPersistentStorage" == "true" && "$RunSensorInReadOnlyMode" == "true" ]]; then
  echo "Read only mode is not supported in sensor without persistent storage. Exiting!"
  exit 1
fi

num_args=${#myArray[@]}

# echo each element in array
# for loop
for (( i=0;i<$num_args;i++)); do
  arg=`echo ${myArray[$i]} | sed "s/\"//g"`
  validate $arg
  if [[ $? == 0 ]]; then
    case $key in
    "CustomerId"|"ActivationId")
        if [[ ! ($val =~ $id_reg) ]]; then
            echo "Error: Invalid $key"
            print_usage_and_exit
        fi
     ;;
    "ImageFile")
        if [[ ! ($val = $ImageFile_req) ]];then
            echo "Error: Invalid $key"
            print_usage_and_exit
        fi
     ;;
    "ImageId")
        if [[ ! ($val =~ $dockerid_reg1) && ! ($val =~ $dockerid_reg2) ]];then
            echo "Error: Invalid $key"
            print_usage_and_exit
        fi
     ;;
    "LogLevel")
        if [[ $val != [0-5] ]]; then
            echo "Invalid input: $key value should lie within range from 0 to 5. Exiting!";
            print_usage_and_exit
        fi
     ;;
     "HostIdSearchDir"|"Storage")
        if [[ ! -d $val ]]; then
            echo "Error: specified path in $key does not exist. Exiting!";
            print_usage_and_exit
        fi
     ;;
     "ConcurrentScan")
        if ! [[ "$val" =~ $integer_reg ]] ; then
            echo "Invalid input: $key value should be an integer. Exiting!";
            print_usage_and_exit
        fi
        if ! [[ $val -ge 1 && $val -le $MaxConcurrentScan_value ]];then
            echo "Invalid input: $key value should lie within range from 1 to 20. Exiting!";
            print_usage_and_exit
        fi
     ;;
     "CpuUsageLimit")
        if ! [[ "$val" =~ $integer_reg ]] ; then
            echo "Invalid input: $key value should be a positive integer, valid range is between 0-100. Exiting!";
            exit 1
        elif [[ "$val" -lt 0 || "$val" -gt 100 ]] ; then
            echo "Invalid input: $key value, valid range is between 0-100. Exiting!";
            exit 1  
        fi
    ;;
    "Proxy")
        if [ -z "$val" ] ; then
            echo "Invalid input: $key value should not be empty. Exiting!";
            print_usage_and_exit
        fi
     ;;
    "ProxyCertFile")
        if [ -z "$val" ] ; then
            echo "Invalid input: $key value should not be empty. Exiting!";
            print_usage_and_exit
        else
            validate_ssl_certificate $val
        fi
     ;;
     "DockerHost")
        if [ -z "$val" ] ; then
            echo "Invalid input: $key value should not be empty. Exiting!";
            print_usage_and_exit
        else
            Dockerd_TCP=$val
        fi
     ;;
     "DockerSocketDirectory")
        if [ -z "$val" ] ; then
            echo "Invalid input: $key value should not be empty. Exiting!";
            print_usage_and_exit
        else 
            DockerSocketDirectoryPathSet=true
        fi
     esac
  else
    print_usage_and_exit 255
  fi
  eval "$key"_defined=1
  eval "$key"_value=$val
done

if [[ -z "$CustomerId_value" ]]; then
    echo "Error: CustomerId must be defined. Exiting!";
    print_usage_and_exit
elif [[ -z "$ActivationId_value" ]]; then
    echo "Error: ActivationId must be defined. Exiting!";
    print_usage_and_exit
elif [[ -z "$Storage_value" ]]; then
    if [[ "$RunSensorWithoutPersistentStorage" == "false" ]]; then
        echo "Error: Storage must be defined or Run Sensor without persistent storage. Exiting!";
        print_usage_and_exit
    fi
elif [[ $Storage_defined -eq 1 && "$RunSensorWithoutPersistentStorage" == "true" ]]; then
    echo "Error: Storage should not be specified when Sensor is to be run without persistent storage. Exiting!"
    echo ""
    print_usage_and_exit
fi

if [[ -z "$ImageFile_value" ]]; then
    ImageFile_value="${Initial_Directory_Name}qualys-sensor.tar"
fi

if [[ ! -z "$LogLevel_value" ]]; then
    LogLevel_Info="--log-level $LogLevel_value"
fi

if [ "$UseDefaults_value" == "true" ]; then
    echo "Non-interactive sensor installation"
fi
echo ""

set_docker_socket_file
check_dockerd_socket
validate_docker_version
handle_cpu_usage_option

Docker_Edition="$(${Docker} version -f '{{.Client.Version}}' | awk -F'-' '{print $2}')"
SeLinux_Status="$(sestatus 2>/dev/null | grep "Current mode:" | awk -F":[ ]*" '{print $2}')"
if [[ $SeLinux_Status == "enforcing" ]]; then
    SeLinux_Opt="--security-opt label=disable"
fi

if [[ -f "${Initial_Directory_Name}"version-info ]] ; then
    QSC_NewVersionInfo="$(cat "${Initial_Directory_Name}"version-info | awk -F'-' '{print $1}')"
else
    echo "New 'Qualys Sensor' image version information not known. Exiting!"
    exit 1
fi

QCS_VersionInfo="$(${Docker} inspect --format '{{.Config.Labels.VersionInfo}}' ${qcs_Name} 2>/dev/null)"
if [[ ! -z "${QCS_VersionInfo}" ]]; then
    # New sensor instance 'qualys-container-sensor' is running.
    Sensor_Name=$qcs_Name
else
    QCS_VersionInfo="$(${Docker} inspect --format '{{.Config.Labels.VersionInfo}}' ${QCS_Name} 2>/dev/null)"
    if [[ ! -z "${QCS_VersionInfo}" ]]; then
        # Old sensor instance 'Qualys-Container-Sensor' is running.
        Sensor_Name=$QCS_Name
    fi
fi

QSC_OldVersionInfo="$(${Docker} inspect --format '{{.Config.Labels.VersionInfo}}'               \
                    $Sensor_Name 2>/dev/null | awk -F' ' '{print $4}' | awk -F'-' '{print $1}')"
if [[ ! -z "$QSC_OldVersionInfo" ]]; then
    Sensor_Default="y"
    QSC_NewMajorNum="$(echo $QSC_NewVersionInfo | awk -F'.' '{print $1}')"
    QSC_OldMajorNum="$(echo $QSC_OldVersionInfo | awk -F'.' '{print $1}')"
    if [ $QSC_NewMajorNum -gt $QSC_OldMajorNum ]; then
        if ! [[ "$UseDefaults_value" == "true" ]]; then 
            read -e -p "Do you want to upgrade '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo} [Y/n]: " Sensor_Proceed
        else 
            echo "Upgrading '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo}... "
        fi
    elif [ $QSC_NewMajorNum -lt $QSC_OldMajorNum ]; then
        if ! [[ "$UseDefaults_value" == "true" ]]; then 
            read -e -p "Do you want to downgrade '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo} [Y/n]: " Sensor_Proceed
        else
            echo "Downgrading '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo}... "
        fi
    else
        QSC_NewMinorNum="$(echo $QSC_NewVersionInfo | awk -F'.' '{print $2}')"
        QSC_OldMinorNum="$(echo $QSC_OldVersionInfo | awk -F'.' '{print $2}')"
        if [ $QSC_NewMinorNum -gt $QSC_OldMinorNum ]; then
            if ! [[ "$UseDefaults_value" == "true" ]]; then 
                read -e -p "Do you want to upgrade '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo} [Y/n]: " Sensor_Proceed
            else 
                echo "Upgrading '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo}... "
            fi
        elif [ $QSC_NewMinorNum -lt $QSC_OldMinorNum ]; then
            if ! [[ "$UseDefaults_value" == "true" ]]; then 
                read -e -p "Do you want to downgrade '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo} [Y/n]: " Sensor_Proceed
            else
                echo "Downgrading '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo}... "
            fi
        else
            QSC_NewPatchNum="$(echo $QSC_NewVersionInfo | awk -F'.' '{print $3}')"
            QSC_OldPatchNum="$(echo $QSC_OldVersionInfo | awk -F'.' '{print $3}')"
            if [ $QSC_NewPatchNum -gt $QSC_OldPatchNum ]; then
                if ! [[ "$UseDefaults_value" == "true" ]]; then 
                    read -e -p "Do you want to upgrade '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo} [Y/n]: " Sensor_Proceed
                else 
                    echo "Upgrading '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo}... "
                fi
            elif [ $QSC_NewPatchNum -lt $QSC_OldPatchNum ]; then
                if ! [[ "$UseDefaults_value" == "true" ]]; then 
                    read -e -p "Do you want to downgrade '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo} [Y/n]: " Sensor_Proceed
                else
                    echo "Downgrading '$Sensor_Name' from version ${QSC_OldVersionInfo} to ${QSC_NewVersionInfo}... "
                fi
            else
                if ! [[ "$UseDefaults_value" == "true" ]]; then 
                    read -e -p "Do you want to rerun '$Sensor_Name' [Y/n]: " Sensor_Proceed
                else
                    echo "Re-running '$Sensor_Name'... "
                fi
            fi
        fi
    fi
    Sensor_Proceed="${Sensor_Proceed:=${Sensor_Default}}"
    if [[ "${Sensor_Proceed}" == "y" || "${Sensor_Proceed}" == "Y" ]] ; then
        ${Docker} rm -f $Sensor_Name 2>&1 > /dev/null
        QCS_VersionInfo="$(${Docker} inspect --format '{{.Config.Labels.VersionInfo}}' ${QCS_Name} 2>/dev/null)"
        if [[ ! -z "${QCS_VersionInfo}" ]]; then
            # Removing old sensor instance 'Qualys-Container-Sensor'.
            ${Docker} rm -f $QCS_Name 2>&1 > /dev/null
        fi
    else
        echo "Quitting"
        exit
    fi
    echo ""
fi

if [[ -f "$ImageFile_value" ]] ; then
    echo "Loading $Sensor_Image image..."
    QSC_Load="$(${Docker} load -i $ImageFile_value)" & Load_Pid=$!
    while kill -0 $Load_Pid &> /dev/null; do 
        printf "▓"
        sleep 0.5
    done
    wait $Load_Pid
    if [[ $? -ne 0 ]]; then
        echo "Docker Load Error: Check the file. Exiting!"
        exit 1
    fi
    echo " (done)!"
else
    echo "Error: $ImageFile_value file does not exist. Exiting!";
    exit 1
fi

if [[ -f "${Initial_Directory_Name}"image-id ]] ; then
    QSC_Image="$(cat "${Initial_Directory_Name}"image-id)"
else
    echo "Qualys Sensor Image ID not known. Exiting!"
    exit 1
fi

QSC_ImageId=${QSC_Image:0:12}
# Tag 'qualys/sensor' image with 'latest QPA Version' label.
QSC_ImageName="$Sensor_Image:$QSC_NewVersionInfo"
${Docker} tag $QSC_ImageId $QSC_ImageName
if [[ $? -ne 0 ]]; then
    echo ""
    echo "Docker Tag Error: Failed to tag $Sensor_Image image. Exiting!"
    exit 1
fi
# Tag 'qualys/sensor' image with 'latest' label too
QSC_ImageName="$Sensor_Image:latest"
${Docker} tag $QSC_ImageId $QSC_ImageName
if [[ $? -ne 0 ]]; then
    echo ""
    echo "Docker Tag Error: Failed to tag $Sensor_Image image. Exiting!"
    exit 1
fi

Proxy_Default="n"
if [[ -z $Proxy_value && ! "$UseDefaults_value" == "true" ]]; then 
    echo ""
    read -e -p "Do you want connection via Proxy [y/N]: " Proxy_Proceed
fi
Proxy_Proceed="${Proxy_Proceed:=${Proxy_Default}}"
if [[ "${Proxy_Proceed}" == "y" || "${Proxy_Proceed}" == "Y" ]] ; then
    Cert_Default="y"
    if [[ -z $Qualys_Https_Proxy_Info ]]; then
        linux_use_proxy /etc/sysconfig/qualys-cloud-agent qualys_https_proxy
    fi
    if [[ -z $Qualys_Https_Proxy_Info ]]; then
        linux_use_proxy /etc/sysconfig/qualys-cloud-agent https_proxy
    fi
    if [[ -z $Qualys_Https_Proxy_Info ]]; then
        linux_use_proxy /etc/environment qualys_https_proxy
    fi
    if [[ -z $Qualys_Https_Proxy_Info ]]; then
        linux_use_proxy /etc/environment https_proxy
    fi
    if [[ -z $Qualys_Https_Proxy_Info ]]; then
        macos_use_proxy /Applications/QualysCloudAgent.app/Contents/Config/proxy qualys_https_proxy
    fi
    if [[ -z $Qualys_Https_Proxy_Info ]]; then
        macos_use_proxy /Applications/QualysCloudAgent.app/Contents/Config/proxy https_proxy
    fi
    if [[ -z $Qualys_Https_Proxy_Info ]]; then
        read -e -p "Enter https proxy settings [<IP/IPv6 addr Or FQDN>:<Port#>]: " Qualys_Https_Proxy;
        if [[ -z $Qualys_Https_Proxy ]]; then
            read -e -p "Enter valid https proxy settings [<IP/IPv6 addr Or FQDN>:<Port#>]: " Qualys_Https_Proxy;
            if [[ -z $Qualys_Https_Proxy ]]; then
                read -e -p "Enter valid https proxy settings [<IP/IPv6 addr Or FQDN>:<Port#>]: " Qualys_Https_Proxy;
            fi
        fi
        if [[ -z $Qualys_Https_Proxy ]]; then
            echo "Invalid https proxy settings. Exiting!"
            exit 1
        fi
        Qualys_Https_Proxy_Info="-e qualys_https_proxy=${Qualys_Https_Proxy}"

        read -e -p "Is there a certificate for proxy '$Qualys_Https_Proxy' [Y/n]: " Cert_Proceed
        Cert_Proceed="${Cert_Proceed:=${Cert_Default}}"
        if [[ "${Cert_Proceed}" == "y" || "${Cert_Proceed}" == "Y" ]] ; then
            read -e -p "Enter https proxy certificate file path: " Proxy_File_Path;
            if [[ -z $Proxy_File_Path ]]; then
                read -e -p "Enter valid https proxy certificate file path: " Proxy_File_Path;
                if [[ -z $Proxy_File_Path ]]; then
                    read -e -p "Enter valid https proxy certificate file path: " Proxy_File_Path;
                fi
            fi
            validate_ssl_certificate $Proxy_File_Path
            if [[ ! "$Proxy_File_Path" =~ ^/ ]]; then
                Proxy_File_Path="$PWD/$Proxy_File_Path"
            fi
            Qualys_Proxy_Cert_File_Info="-v ${Proxy_File_Path}:/etc/qualys/qpa/cert/custom-ca.crt"
        fi
    fi
fi

if [[ ! -z $Proxy_value ]]; then
    echo ""
    echo "Connecting via proxy '$Proxy_value'"
    Qualys_Https_Proxy_Info="-e qualys_https_proxy=${Proxy_value}"
    if [[ ! -z $ProxyCertFile_value ]]; then
        if [[ ! "$ProxyCertFile_value" =~ ^/ ]]; then
            ProxyCertFile_value="$PWD/$ProxyCertFile_value"
        fi
        Qualys_Proxy_Cert_File_Info="-v ${ProxyCertFile_value}:/etc/qualys/qpa/cert/custom-ca.crt"
    fi
fi

echo ""
PersistentVolumeMappings=""

if [[ "$RunSensorWithoutPersistentStorage" == "true" ]]; then
   PersistentVolumeMappings="-v $DockerSocketDirectory_value:/var/run" 
   if [[ $HostIdSearchDir_defined -eq 1 ]]; then
        PersistentVolumeMappings="$PersistentVolumeMappings  \
                                 -v $HostIdSearchDir_value:/usr/local/qualys/qpa/data/conf/agent-data"
   fi
else
    if [[ ! "$Storage_value" =~ ^/ ]]; then
        Storage_value="$PWD/$Storage_value"
    fi
    PersistentVolumeMappings=" -v $HostIdSearchDir_value:/usr/local/qualys/qpa/data/conf/agent-data \
                               -v $DockerSocketDirectory_value:/var/run  \
                               -v $Storage_value:/usr/local/qualys/qpa/data "
fi

QSC_Id="$(${Docker} run $SeLinux_Opt -d                                         \
        --restart on-failure                                                    \
        $SensorInReadOnlyMode_value                                             \
        $Cpu_Limit_Option_String                                                \
        $PersistentVolumeMappings                                               \
        $Dockerd_TCP_Socket_Env                                                 \
        $Qualys_Proxy_Cert_File_Info                                            \
        $Qualys_Https_Proxy_Info                                                \
        -e ACTIVATIONID=$ActivationId_value                                     \
        -e CUSTOMERID=$CustomerId_value                                         \
        --net=host                                                              \
        --name $qcs_Name                                                        \
        $QSC_ImageName                                                          \
        $LogLevel_Info                                                          \
        --scan-thread-pool-size $ConcurrentScan_value                           \
        $RegistryScan_value                                                     \
        $CICDDeployedSensor_value                                               \
        $EnableAutoUpdate_value                                                 \
        $EnableDebugLogsOnConsole_value                                         \
        $SensorWithoutPersistentStorage_value)"
if [[ $? -ne 0 ]]; then
    echo ""
    echo "Docker Run Error: Failed to start Qualys Containerized Sensor($qcs_Name). Exiting!"
    echo ""
    exit 1
else
    echo "Started '$qcs_Name', container ID: ${QSC_Id:0:12} successfully."
    echo ""
    
    if [[ "$RunSensorWithoutPersistentStorage" == "true" ]]; then
        echo "For more details, please refer /usr/local/qualys/qpa/data/logs/qpa.log file relative to Sensor container."
    elif [[ ! -z "$EnableDebugLogsOnConsole_value" ]]; then 
          echo "Logs are sent to console as requested, For more details please use command 'docker logs $qcs_Name'."
    else
         echo "For more details, please refer '$Storage_value/logs/qpa.log' file."
    fi
    echo ""
    exit 0
fi
