#!/bin/bash
#
#  This is a bash script to update qualys sensor to latest version
#  This script runs on docker host and launches the updated version of sensor
#  Inputs to this script are received from the old sensor, includes volume
#  mounts, environment variables and arguments that old sensor was run with
#

echo "This script is intended to be executed by Qualys Container Sensor only. Not to be used otherwise."
echo ""

print_exit_message()
{
    exitMessage="The autoupdate script can only be executed by auto-update process by qualys-container-sensor. Bailing out!"
    echo "$exitMessage"
}

Docker="docker "
CpuUsageLimit_value="20" # Default CPU usage limit value is 20% of overall CPU available
Use_Cpus_Option="false"
Number_Of_Cpu_Cores_OnHost="0"
Cpu_Limit_Option_String=""


# Check if this is being run from qualys-container-sensor
qualysContainerID="$(${Docker} ps --no-trunc -aqf name=qualys-container-sensor-old)"
if [[ -z $qualysContainerID ]]; then
    print_exit_message
    exit 1
fi

#confirm the current container ID against qualys one using /proc/self/cgroup
cgroup_file="/proc/self/cgroup"
if [[ ! -e $cgroup_file ]]; then
    print_exit_message
    exit 1
fi

if ! grep -q $qualysContainerID ${cgroup_file}; then
    print_exit_message
    exit 1
fi

ParentPID=$PPID
#
#  This script is to be run by qpa only. When qpa runs this script, it invokes
#  shell which executes the script, so parent ID is shell and in order to get
#  the name of the process that actually invokes the script, we have to look at the
#  grandparent process
#
ParentProcName="$(ps -o comm= -p $(ps -o ppid= -p $ParentPID))"
ExpectedProc="qpa"
if [[ "$ParentProcName" != "qpa" ]]; then
    print_exit_message
    exit 1
fi

QSC_Name=" qualys-container-sensor "
Sensor_Image=" qualys/sensor"
QSC_Pers_Storage=""
QSC_Data_Dir="/usr/local/qualys/qpa/data"
Setup_Dir="$(echo "$0" | awk -F'autoupdate.sh' '{print $1}')"
ImageFile_value="${Setup_Dir}qualys-sensor.tar"
Min_Major_Ver="1"
Min_Minor_Ver="10"

MaxConcurrentScan_value="20"
ImgScanThreadPool_arg="--image-scan-pool-size"
ImgScanThreadPool_value="2"
ContScanThreadPool_arg="--contr-scan-pool-size"
ContScanThreadPool_value="2"
ConcurrentScanThreadPool_arg="--scan-thread-pool-size"
ConcurrentScanThreadPoolArgProvided=false

StartDelay_arg="--start-delay"

RunSensorWithoutPersStorage="false"
SensorWithoutPersStorageKey="--sensor-without-persistent-storage"

SecurityOptionsArray=()
EnvArray=()
VolumesArray=()
ArgsArray=()
CpuLimitArray=()
num_args=0
index=0

get_key()
{
    echo $1|awk -F= '{printf $1}'
}

get_val()
{
    echo $1|awk -F= '{printf $2}'
}

get_mount_source()
{
    echo $1|awk -F: '{printf $1}'
}

get_mount_dest()
{
    echo $1|awk -F: '{printf $2}'
}

validate_docker_version()
{
# Validate docker server version
    Docker_Server_Major_Ver="$(${Docker} version -f '{{.Server.Version}}' 2>/dev/null | awk -F'.' '{print $1}')"
    Docker_Server_Minor_Ver="$(${Docker} version -f '{{.Server.Version}}' 2>/dev/null | awk -F'.' '{print $2}')"

    if [ -z "$Docker_Server_Major_Ver" ]; then
        echo "Cannot connect to the Docker daemon. Is the docker daemon running on this host?"
        exit 1
    fi
    if [[ $Docker_Server_Major_Ver -lt $Min_Major_Ver ]]; then
        echo "Minimum docker server version($Min_Major_Ver.$Min_Minor_Ver.0) requirement fail"
        exit 1
    elif [[ $Docker_Server_Major_Ver -eq $Min_Major_Ver && $Docker_Server_Minor_Ver -lt $Min_Minor_Ver ]]; then
        echo "Minimum docker server version($Min_Major_Ver.$Min_Minor_Ver.0) requirement fail"
        exit 1
    fi
}

check_kernel_support_for_cpu_limit_quota()
{

  # First check if the docker info -f command is supported, it is not supported
  # on 1.12 and maybe the case for some other immediate version
  # If not, then check presence of files cpu.cfs_period_us and cpu.cfs_quota_us
  # in /sys/fs/cgroup/cpu,cpuacct/ 

    if $Docker info -f '{{.CPUCfsPeriod}}' 1> /dev/null 2>&1; then
      CPUCfsPeriod=false
      CPUCfsQuota=false

      CPUCfsPeriod=$($Docker info -f '{{.CPUCfsPeriod}}')
      CPUCfsQuota=$($Docker info -f '{{.CPUCfsQuota}}')

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
    Docker_Client_Major_Ver="$($Docker version -f '{{.Client.Version}}' 2>/dev/null | awk -F'.' '{print $1}')"
    Docker_Client_Minor_Ver="$($Docker version -f '{{.Client.Version}}' 2>/dev/null | awk -F'.' '{print $2}')"

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
  Number_Of_Cpu_Cores_OnHost="$(cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l)"
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
    # If no, do not provide cpu support option 

    check_kernel_support_for_cpu_limit_quota
    
    if [ "$CpuLimit_CpuQuota_Kernel_Support" = true  ]; then 
        if [ $CpuUsageLimit_value -ne 0 ]; then
            check_cpu_limit_option
            get_number_of_cpu_cores
            build_cpu_limit_option_string
        fi
    fi
}

get_scan_thread_pool_value()
{
# This function takes in the arguments from old version (if any) and converts
# it to argument compatible with lastet version
# Moreover, it is assumed that this script will always be run with latest
# sensor and so will not work in case this was copied to work with on old
# version (1.1.x and less)

    if [ "$ConcurrentScanThreadPoolArgProvided" = false ]; then
        ConcurrentScanThreadPool_value=$(($ImgScanThreadPool_value+$ContScanThreadPool_value))
        if [[ $ConcurrentScanThreadPool_value -gt $MaxConcurrentScan_value ]]; then
            ConcurrentScanThreadPool_value=$MaxConcurrentScan_value
        fi
    fi
}

while getopts "a:e:s:c:v:" opt;
do
    case ${opt} in
    a) #process option a : arguments to qpamon
       num_args=${#ArgsArray[@]}
       ArgsArray[$num_args]=$OPTARG
        ;;
    e) #process option e : env variables like actID, custID, proxy
        num_args=${#EnvArray[@]}
        EnvArray[$num_args]=$OPTARG
        ;;
    s) #process option s : security label
        num_args=${#SecurityOptionsArray[@]}
        SecurityOptionsArray[$num_args]=$OPTARG 
        ;;
    c) #process option c : CPU usage limit
        num_args=${#CpuLimitArray[@]}
        CpuLimitArray[$num_args]=$OPTARG
        ;;
    v) #process option v : volumes to be mouneted
        num_args=${#VolumesArray[@]}
        VolumesArray[$num_args]=$OPTARG
        ;;
    esac
done


#process each of the arguments
Volumes=""
EnvVars=""
SecurityOptions=""
Arguments=""


echo "Image file: $ImageFile_value"
echo ""

#now, let's get env vars and prepend -e 
num_args=${#EnvArray[@]}
if [[ num_args -ge 2 ]]; then
    prependArg=" -e "
    Docker_Arg="DOCKER_HOST"
    for (( i=0;i<$num_args;i++)); do
        Env_Var_Arg="$(echo ${EnvArray[$i]} | awk -F= '{print $1}')"
        if [[ $Env_Var_Arg = $Docker_Arg ]]; then 
          Env_Var_Docker_Val="$(echo "${EnvArray[$i]}" | awk -F= '{print $2}')"
          Dockerd_Tcp_Sock=" -H "$Env_Var_Docker_Val
          Docker=$Docker$Dockerd_Tcp_Sock
       fi
       EnvVars=$EnvVars$prependArg${EnvArray[$i]} 
    done
else
    echo "Insufficient number of environment variables"
    exit 1
fi

validate_docker_version 

#time for security options
num_args=${#SecurityOptionsArray[@]}
prependSec=" --security-opt "
for (( i=0;i<$num_args;i++)); do
   SecurityOptions=$SecurityOptions$prependSec${SecurityOptionsArray[$i]}
done

#Let's get cpu limit values
num_args=${#CpuLimitArray[@]}
if [[ num_args -ge 1 ]]; then
    prependArg=" "
    for (( i=0;i<num_args;i++)); do
      key=$(get_key "${CpuLimitArray[$i]}")
      val=$(get_val "${CpuLimitArray[$i]}")
      CpuLimit=$CpuLimit$prependArg$key$prependArg$val
    done
else
    handle_cpu_usage_option
    CpuLimit=$Cpu_Limit_Option_String
fi  

#arguments 
num_args=${#ArgsArray[@]}
prependArg=" "
for (( i=0;i<num_args;i++)); do
    key=$(get_key "${ArgsArray[$i]}")
    val=$(get_val "${ArgsArray[$i]}")
    
# start-delay argument has been removed 1.2.x onwards. So if this argument is
# passed by older sensor to this script, it should be ignored
    if [[ $key == $StartDelay_arg ]]; then
        continue
# Capturing values for thread pool parametes if they were provided in old
# format of "--img-scan-pool-size" and "--contr-scan-pool-size"
# These are used to translate to thread pool parameter that is acceptable for
# new sensor "--scan-thread-pool-size"
# If --scan-thread-pool-size is provided, then this is honored irrespective of
# presence of other 2 arguments. However, this will never be a valid scenario.
    elif [[ $key == $ImgScanThreadPool_arg ]]; then
        ImgScanThreadPool_value=$val
    elif [[ $key == $ContScanThreadPool_arg ]]; then 
        ContScanThreadPool_value=$val
    elif [[ $key == $ConcurrentScanThreadPool_arg ]]; then
        ConcurrentScanThreadPoolArgProvided=true
        ConcurrentScanThreadPool_value=$val
    else 
        if [[ $key == $SensorWithoutPersStorageKey ]]; then
            RunSensorWithoutPersStorage="true" 
        fi
        Arguments=$Arguments$prependArg$key$prependArg$val
    fi
done

get_scan_thread_pool_value
Arguments=$Arguments$prependArg$ConcurrentScanThreadPool_arg$prependArg$ConcurrentScanThreadPool_value

#let's get volumes
#iterate over array and prepend -v
num_args=${#VolumesArray[@]}
num_required_volume_mounts=3
if [[ $RunSensorWithoutPersStorage == "true" ]]; then
    # In case of sensor without persistent storage there is only one 
    # mandatory volume mapping - /var/run:/var/run
    # Another optional mount can be for proxy cert file
    num_required_volume_mounts=1 
fi
if [[ $num_args -ge $num_required_volume_mounts ]]; then
    prependVol=" -v "
    for (( i=0;i<$num_args;i++)); do
       Volumes=$Volumes$prependVol${VolumesArray[$i]}
   done
else
    echo "Insufficient number of volume mounts"
    exit 1
fi


#load qualys-sensor.tar
if [[ -f "$ImageFile_value" ]] ; then
    echo "Loading $Sensor_Image image..."
    QSC_Load="$(${Docker} load -i $ImageFile_value)" & Load_Pid=$!
    while kill -0 $Load_Pid &> /dev/null; do
       sleep 0.5
    done
    wait $Load_Pid
    if [[ $? -ne 0 ]]; then
        echo "Docker Load Error: Check the file."
        exit 1
    fi
    echo " (done)!"
else
    echo "Error: $ImageFile_value file does not exist";
    exit 1
fi

if [[ -f "${Setup_Dir}"/image-id ]] ; then
    QSC_Image="$(cat "${Setup_Dir}"/image-id)"
else
    echo "Qualys Sensor Image ID not known"
    exit 1
fi

if [[ -f "${Setup_Dir}"/version-info ]] ; then
    QSC_NewVersionInfo="$(cat "${Setup_Dir}"/version-info | awk -F'-' '{print $1}')"
else
    echo "New 'Qualys Sensor' image version information not known"
    exit 1
fi

QSC_ImageId=${QSC_Image:0:12}
Image_Name=$Sensor_Image
Sensor_Image="${Sensor_Image}:latest"
${Docker} tag $QSC_ImageId $Sensor_Image
if [[ $? -ne 0 ]]; then
    echo "Docker Tag Error: Failed to tag $Sensor_Image image."
    exit 1
fi

Sensor_Image="$Image_Name:$QSC_NewVersionInfo"
${Docker} tag $QSC_ImageId $Sensor_Image
if [[ $? -ne 0 ]]; then
    echo "Docker Tag Error: Failed to tag $Sensor_Image image."
    exit 1
fi

#Time to form docker run command
QSCRunCommand="$(${Docker} run $SecurityOptions                     \
                -d $Volumes                                         \
                $Dockerd_TCP_Socket_Env                             \
                $EnvVars                                            \
               --net=host                                           \
               --restart=on-failure                                 \
               $CpuLimit                                            \
               --name $QSC_Name                                     \
               $Sensor_Image                                        \
               $Arguments                                           \
               --enable-auto-update)"
if [[ $? -ne 0 ]]; then
    echo "Docker Run Error: Failed to start Qualys Containerized Sensor($QSC_Name)."
    exit 1
else
    echo "Started updated QSC Sensor"
    exit 0
fi
