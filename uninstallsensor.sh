#!/bin/bash

#
# This is bash script to uninstall qualys/sensor from host.
# This script runs on docker host and kill the qualys/sensor
# container instance either 'qualys-container-sensor' or
# 'Qualys-Container-Sensor'.
#

qcs_Name="qualys-container-sensor"
QCS_Name="Qualys-Container-Sensor"
Sensor_Image="qualys/sensor"
Lable_Name="Qualys Sensor Image"
QCS_Storage="/usr/local/qualys/qpa/data"
Storage_Value=""
Sensor_Name=""
Is_Sensor_Installed="false"
Silent_value="false"
Docker_Sock_File="/var/run/docker.sock"
Dockerd_TCP=""
Dockerd_TCP_Default="n"
Docker_Arg=""
Docker="docker "
Dockerd_TCP_Arg=""
IMAGE_SCANNING_TAG="QCS-Image-Scanning-"

usage()
{
    echo "Usage:"
    echo "uninstallsensor.sh --help or -h <To print help message>"
    echo "uninstallsensor.sh --silent or -s <Optional parameter to run script in non-interactive mode>"
    echo "uninstallsensor.sh DockerHost=<<IPv4 address or FQDN>:<Port#>> <Address on which docker daemon is configured to listen>"
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

validate_dockerd_socket()
{
    # if $Dockerd_TCP does not have ":<port#>", add default 2375 - will have to modify later to accomodate 2376 for tcp tls  
    port_num="$(echo $Dockerd_TCP | awk -F':' '{print $2}')"
    if [[ -z $port_num ]]; then
        port_num="2375"
        Dockerd_TCP=$(echo $Dockerd_TCP":"$port_num)
   fi
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
    
    Docker_Arg=" -H ${1} "
    Docker="${Docker} ${Docker_Arg}"
}

check_dockerd_socket()
{
    # check if /var/run/docker.sock is present, if yes then it is preferred over tcp details provided by customer
    if [ -e ${Docker_Sock_File} ]; then
        return;
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

    if [ "$Silent_value" == "false" ]; then
        echo ""
        read -e -p "Docker daemon is not listening on unix domain socket. Is docker daemon configured to listen on TCP socket? [y/N]: " Dockerd_TCP_Proceed
    elif [ "$Silent_value" == "true" ]; then
        echo ""
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
        if [[ -z $Dockerd_TCP ]]; then
            echo "Invalid TCP details for docker daemon"
            exit 1
        fi
        
        validate_dockerd_socket 
        set_dockerd_host $Dockerd_TCP
    else
        echo ""
        echo "Docker daemon is not listening on unix domain socket. Details of \"DockerHost\" required. Exiting."
        exit 1
    fi
}

validate()
{
    if [[ $# -lt 1 ]]; then
        echo "missing parameter to validate"
        return 255;
    fi
    key=$(get_key "$*")
    val=$(get_val "$*")
    if [[ "$key" != "DockerHost" ]]; then
            echo "Error: Invalid key name in $1"
            return 255
    fi
    if [[ -z "$key" || -z "$val" ]]; then
          echo "Error: Key or Value missing in [$1]"
          return 255;
    fi
    return 0
}

if [[ $# -gt 2 ]]; then
  print_usage_and_exit 0
fi

myArray=()
index=0
whitespace="[[:space:]]"
for i in "$@"
do
    if [[ $i =~ $whitespace ]]; then
        i=\"$i\"
    fi

    if [[ $i == "--help" || $i == "-h" ]]; then
        print_usage_and_exit
    elif [[ $i == "--silent" || $i == "-s" ]]; then
        Silent_value="true"
    else
        myArray[$index]="$i"
        index=$(( $index + 1 ))
    fi
done

num_args=${#myArray[@]}

if [[ $num_args -gt 2 ]]; then
    exit
fi

for (( i=0;i<$num_args;i++)); do
  arg=`echo ${myArray[$i]} | sed "s/\"//g"`
  validate $arg
  if [[ $? == 0 ]]; then
    if [[ "$key" == "DockerHost" ]]; then
        if [ -z "$val" ] ; then
            echo "Invalid input: $key value should not be empty";
            exit 1
        else
            Dockerd_TCP=$val
        fi
    fi
  else
    print_usage_and_exit 255
  fi
done

if [[ "$Silent_value" == "true" ]]; then 
    echo "Non-interactive sensor uninstallation."
fi
check_dockerd_socket

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

if [[ ! -z "${QCS_VersionInfo}" ]]; then
    Is_Sensor_Installed="true"
    Sensor_Default="y"
    echo ""
    if ! [[ "$Silent_value" == "true" ]]; then 
        read -e -p "Do you want to remove sensor container '$Sensor_Name' [Y/n]: " Sensor_Proceed
    else
        echo "Removing sensor container '$Sensor_Name'."
    fi
    Sensor_Proceed="${Sensor_Proceed:=${Sensor_Default}}"
    if [[ "${Sensor_Proceed}" == "y" || "${Sensor_Proceed}" == "Y" ]] ; then
        binds=( $(${Docker} inspect --format '{{.HostConfig.Binds}}' ${Sensor_Name} 2>/dev/null) )
        for i in "${binds[@]}"; do
            Storage_Value="$(echo "${i}" | sed "s/\[//g")"
            Storage_Value="$(echo "${Storage_Value}" | sed "s/\]//g")"
            Storage_Value="$(echo "${Storage_Value}" | grep "${QCS_Storage}$")"
            if [[ ! -z ${Storage_Value} ]]; then
                Storage_Value="$(echo "${Storage_Value}" | awk -F':' '{print $1}')"
                if [[ ! ${Storage_Value} =~ /$ ]]; then
                    Storage_Value="${Storage_Value}/"
                fi
                break;
            fi
        done
        ${Docker} rm -f ${Sensor_Name} 2>&1 > /dev/null
        if [[ $? -ne 0 ]]; then
            echo "Docker: Error in removing container instance '$Sensor_Name'."
            exit 1
        fi
    else
        echo "Quitting"
        echo ""
        exit
    fi

    if [[ "${Sensor_Proceed}" == "y" || "${Sensor_Proceed}" == "Y" ]] ; then
	ids=( $(docker ${Dockerd_TCP_Arg} ps -aq --filter "name=$IMAGE_SCANNING_TAG"))
	len=${#ids[@]}
	for (( i=0; i<${len}; i++ ));
	do
	  docker ${Dockerd_TCP_Arg} rm -f ${ids[$i]} 2>&1 > /dev/null
	done
    fi
fi

# Silently remove all containers created using 'Qualys Sensor Image' 
container_names=( $(${Docker} ps -a --format {{.Names}}) )
container_names_len=${#container_names[@]}
for (( i=0; i<${container_names_len}; i++ ));
do
    if [[ $(${Docker} inspect --format '{{.Config.Labels.name}}' ${container_names[$i]} 2>/dev/null) == ${Lable_Name} ]]; then
        ${Docker} rm -f ${container_names[$i]} 2>&1 > /dev/null
    fi
done

# Silently remove intermediate image scanning containers
if [[ $((${Docker} ps -a --format {{.Names}} 2>/dev/null) | grep 'QCS-Image-Scanning-[a-z0-9]\{64\}') ]]; then
    ${Docker} rm -f $(${Docker} ps -a --format {{.Names}} | grep 'QCS-Image-Scanning-[a-z0-9]\{64\}') 2>&1 > /dev/null
fi

image_names=( $(${Docker} images --format {{.Repository}}) )
image_tags=( $(${Docker} images --format {{.Tag}}) )
image_ids=( $(${Docker} images --format {{.ID}}) )

image_names_len=${#image_ids[@]}
for (( i=0; i<${image_names_len}; i++ ));
do
    Image_Default="y"
    if [[ $(${Docker} inspect --format '{{.Config.Labels.name}}' ${image_ids[$i]} 2>/dev/null) == ${Lable_Name} ]]; then
        echo ""
        Is_Sensor_Installed="true"
        if [[ ${image_names[$i]} != '<none>' && ${image_tags[$i]} != '<none>' ]];then
            if ! [[ "$Silent_value" == "true" ]]; then
                read -e -p "Do you want to remove sensor image '${image_names[$i]}:${image_tags[$i]}' [Y/n]: " Image_Proceed
            else
                echo "Removing sensor image '${image_names[$i]}:${image_tags[$i]}'"
            fi
        else
            if ! [[ "$Silent_value" == "true" ]]; then
                read -e -p "Do you want to remove dangling sensor image '${image_ids[$i]}' [Y/n]: " Image_Proceed
            else
                echo "Removing dangling sensor image '${image_ids[$i]}'"
            fi
        fi
        Image_Proceed="${Image_Proceed:=${Image_Default}}"
        if [[ "${Image_Proceed}" == "y" || "${Image_Proceed}" == "Y" ]] ; then
            if [[ ${image_names[$i]} != '<none>' && ${image_tags[$i]} != '<none>' ]]; then
                ${Docker} rmi -f ${image_names[$i]}:${image_tags[$i]} 2>&1 > /dev/null
                if [[ $? -ne 0 ]]; then
                    echo "Docker: Error in removing sensor image '${image_names[$i]}:${image_tags[$i]}'."
                fi
                else
                    ${Docker} rmi -f ${image_ids[$i]} 2>&1 > /dev/null
                    if [[ $? -ne 0 ]]; then
                        echo "Docker: Error in removing dangling sensor image '${image_ids[$i]}'."
                    fi
                fi
        fi
    fi
done

if [[ ! -z ${Storage_Value} ]]; then
    Storage_Default="n"
    if ! [[ "$Silent_value" == "true" ]]; then 
        echo ""
        echo "Clearing sensor's persistent storage '${Storage_Value}'."
        read -e -p "This is not recommended, still want to clear [y/N]: " Storage_Proceed
    fi
    Storage_Proceed="${Storage_Proceed:=${Storage_Default}}"
    if [[ "${Storage_Proceed}" == "y" || "${Storage_Proceed}" == "Y" ]] ; then
        find ${Storage_Value} -name 'conf' -type d -exec rm -rf {} + 2>/dev/null
        find ${Storage_Value} -name 'logs' -type d -exec rm -rf {} + 2>/dev/null
        find ${Storage_Value} -name 'manifests' -type d -exec rm -rf {} + 2>/dev/null
        find ${Storage_Value} -name 'setup' -type d -exec rm -rf {} + 2>/dev/null
        find ${Storage_Value} -name 'temp' -type d -exec rm -rf {} + 2>/dev/null
        find ${Storage_Value} -name 'static_scan_temp' -type d -exec rm -rf {} + 2>/dev/null
        find ${Storage_Value} -name 'SensorInfo.json' -delete 2>/dev/null
        find ${Storage_Value} -name '*ChangeList.db' -delete 2>/dev/null
        find ${Storage_Value} -name '*SnapshotVM.db' -delete 2>/dev/null
    fi
fi

if [ -d "/Applications/QualysContainerSensor.app/" ];then
     pkgutil --forget com.qualys.pkg.sensor
     rm -rf /Applications/QualysContainerSensor.app
fi     

if ! [[ "$Is_Sensor_Installed" == "true" ]]; then
    echo ""
    echo "Qualys Sensor not found on host!";
fi

echo ""
