#!/bin/bash
#
#  This is a bash script to update qualys sensor to latest version in
#  kubernetes environment
#  This script runs on master and performs rolling update of sensor pods
#  Input to this script is registry url that the customer image will be pushed
#  to so that it will be available from all nodes
#  Prerequisites:
#  1. The tar package should be downloaded and copied to master
#  2. In case of authenticated registry, docker login should be performed
#  before launching the script
#  3. The registry provided should be accessible from all the nodes
#
#  Requirements:
#  1. It is expected that deployment yml should be manually changed to have
#  full path to image, activation ID, customer ID, proxy details, volume mounts
#
#######--------######### 
# PARSE INPUT TO REGISTRY URL

Registry_Url=""
Registry_Url_defined=false
Rollback_done=false
Rollout_pid=""
Rollback_pid=""
QSC_ImageId=""
Container_Stuck_In_Creating_Mode=0
Container_Stuck_In_Creating_Mode_Max=6
Pod_Stuck_In_Pending_State_Max=10

Dockerd_TCP=""
Dockerd_TCP_Default="n"
Docker_Arg=""
Docker="docker "
Docker_Sock_File="/var/run/docker.sock"

apipe=/tmp/aux-qualys-rolling-update
pipe=/tmp/qualys-rolling-update
Script_Directory_Name="$(echo "$0" | awk -F'k8s-rolling-update.sh' '{echo $1}')"
Log_File="${Script_Directory_Name}"qualys-sensor-update.log
script_pid=$$
declare -A NodeStateMap

adddate() 
{
    while IFS= read -r line; do
        print $line
    done
}

print()
{
    text_to_print=$@
    if [[ ! -z $text_to_print ]];then
    	echo $text_to_print
        text_to_print="["$(date -u)"]: "$text_to_print
    fi
    echo $text_to_print >> $Log_File 
}

usage()
{
    print "Usage: " 
    print "k8s-rolling-update.sh --help or -h <To print help message>"
    print "k8s-rolling-update.sh Registry_Url=<<Registry URL>:<Port #>>"
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

cleanup()
{
    if [[ ! -z $QSC_ImageId ]]; then
        $Docker rmi -f $QSC_ImageId &> /dev/null
        if [[ $? -ne 0 ]]; then
            print "Could not remove image "$QSC_ImageId 
        else
            print "Successfully removed image "$QSC_ImageId
      	fi
    fi
}

exit_if_no_kubectl()
{
    kubectl version &> /dev/null
    if [[ 0 -ne $? ]]; then
        print "Kubectl not available, cannot perform update. Exiting"
        exit 1
    fi
}

exit_if_no_qualys_ds()
{
    ret="$(kubectl get ds --all-namespaces --selector=k8s-app=qualys-cs-sensor)"
    if [[ -z $ret ]]; then
    	print "Cannot find qualys-container-sensor daemonset. Aborting rolling update."
	exit 1
    fi
    
}

validate_dockerd_socket()
{
    # if $Dockerd_TCP does not have ":<port#>", add default 2375 - Will have to modify later to accomodate 2376 for TCP TLS  
    port_num="$(echo $Dockerd_TCP | awk -F':' '{printf $2}')"
    if [[ -z $port_num ]]; then
        port_num="2375"
        Dockerd_TCP=$(echo $Dockerd_TCP":"$port_num)
   fi
}

set_dockerd_host()
{
    if [[ $# -ne 1 ]]; then
        print "Invalid TCP details for docker daemon."
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

    read -e -p "Docker daemon is not listening on unix domain socket. Is docker daemon configured to listen on TCP socket? [y/N]: " Dockerd_TCP_Proceed

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
            print "Invalid TCP details for docker daemon"
            exit 1
        fi
        
        validate_dockerd_socket 
        set_dockerd_host $Dockerd_TCP
    fi
}


create_pipes()
{
    rm -f $pipe
    if [[ ! -p $pipe ]]; then
        mkfifo $pipe
    fi

    rm -f $apipe
    if [[ ! -p $apipe ]]; then
        mkfifo $apipe
    fi
 
    echo "Unavailable" >$apipe &
}

delete_pipes()
{
    rm -f $pipe
    rm -f $apipe
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
        print "missing parameter to validate"
        return 255;
    fi
    key=$(get_key "$*")
    val=$(get_val "$*")
    if [[ "$key" != "Registry_Url" ]]; then
        print "Error: Invalid key name in $1"
        return 255
    fi
    if [[ -z "$key" || -z "$val" ]]; then
        print "Error: Key or Value missing in [$1]"
        return 255;
    fi
    return 0
}

rollback()
{
   if [ "$Rollback_done" = true ]; then
        # rollback is called again from manage_watch_background_process means that rollback has failed, delete ds
        print "Rollback has failed, deleting the qualys sensor daemonset as it is not successfully rolled back"
        kubectl delete ds qualys-container-sensor -n $qualys_namespace | adddate  
        delete_pipes
        kill_background_processes
        exit 0
   fi
   
   print "Rolling back"
   Rollback_done=true

   cleanup
   kill_process_if_running $Rollout_pid

   kubectl rollout undo daemonset qualys-container-sensor -n $qualys_namespace 2>&1 | adddate 
   if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
       rollback
   fi

   watch_rollback_status &

   Rollback_pid=$!

   manage_watch_background_process $Rollback_pid Rollback

   delete_pipes 
   kill_background_processes
   exit 0
}

watch_rollout_status()
{
    # get namespace for qualys-container-sensor
    qualys_namespace="kube-system"
    qualys_namespace="$(kubectl get ds --all-namespaces --selector=k8s-app=qualys-cs-sensor -o jsonpath="{.items[*].metadata.namespace}" 2>/dev/null)"
    if [[ -z $qualys_namespace ]]; then
    	print "Unable to get namespace in which qualys-container-sensor daemonset is running, using value "kube-system""
    fi


    pipe=/tmp/qualys-rolling-update
    apipe=/tmp/aux-qualys-rolling-update
    if [[ ! -p $pipe ]]; then
        mkfifo $pipe
    fi
    if [[ ! -p $apipe ]]; then
        mkfifo $apipe
    fi

    # do this in a thread
    kubectl rollout status ds/qualys-container-sensor -n $qualys_namespace 2>&1 | adddate 
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        # write to pipe - rollout successful
        echo "Rollout_successful" >$pipe &
        echo "Added" >$apipe &
    else
       # write to pipe - rollout failed
        echo "Rollout_failed" >$pipe &
        echo "Added" >$apipe &
    fi
    exit 0
}

watch_rollback_status()
{
    # get namespace for qualys-container-sensor
    qualys_namespace="kube-system"
    qualys_namespace="$(kubectl get ds --all-namespaces --selector=k8s-app=qualys-cs-sensor -o jsonpath="{.items[*].metadata.namespace}" 2>/dev/null)"
    if [[ -z $qualys_namespace ]]; then
    	print "Unable to get namespace in which qualys-container-sensor daemonset is running, using value "kube-system""
    fi

    apipe=/tmp/aux-qualys-rolling-update
    if [[ ! -p $pipe ]]; then
        mkfifo $pipe
    fi
    if [[ ! -p $apipe ]]; then
        mkfifo $apipe
    fi

    # do this in a thread
    kubectl rollout status ds/qualys-container-sensor -n $qualys_namespace 2>&1 | adddate 
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        # write to pipe - rollout successful
        echo "Rollback_successful" >$pipe &
        echo "Added" >$apipe &
    else
        # write to pipe - rollout failed
        echo "Rollback_failed" >$pipe &
        echo "Added" >$apipe &
    fi
    exit 0
}


kill_process_if_running()
{
    if [[ $# -ne 1 ]]; then
        return
    fi
    
    pid_to_kill=${1}

    if ps "$pid_to_kill" >/dev/null; then 
        kill -9 $pid_to_kill >/dev/null 2>&1
    fi
}

kill_background_processes()
{
    kill_process_if_running $Rollout_pid 
    kill_process_if_running $Rollback_pid 
    pid_to_kill="$(ps -ef | sort -n | grep "k8s-rolling-update.sh" | awk '{print $2}' | grep -v $script_pid)"
    kill -9 $pid_to_kill >/dev/null 2>&1
}

is_pod_backing_off()
{
    pod_failure_reason=$(kubectl get pods -n $qualys_namespace --selector=name=qualys-container-sensor -o jsonpath="{.items[*].status.containerStatuses..state..reason}")
    if [[ 0 -ne `echo $pod_failure_reason | grep --ignore-case -c BackOff` || 0 -ne `echo $pod_failure_reason | grep --ignore-case -c Invalid` || 0 -ne `echo $pod_failure_reason | grep --ignore-case -c CreateContainerConfigError` ]]; then
        print "Pod failure reason is : "$pod_failure_reason
        return 0
    fi
    return 1 
}

is_pod_stuck_in_creating_state()
{
    # check if pod is in ContainerCreating state
    # check if reason is ContainersNotReady
    pod_state="$(kubectl get pods -n $qualys_namespace --selector=name=qualys-container-sensor -o jsonpath="{.items[*].status.containerStatuses..state..reason}")"
    if [[ "$pod_state" = "ContainerCreating" ]]; then
        pod_condition_reason="$(kubectl get pods -n $qualys_namespace --selector=name=qualys-container-sensor -o jsonpath="{.items[*].status.conditions..reason}")"
        if [[ 0 -ne `echo $pod_condition_reason | grep --ignore-case -c ContainersNotReady` ]]; then
            ((Container_Stuck_In_Creating_Mode++))
            if [[ $Container_Stuck_In_Creating_Mode -eq $Container_Stuck_In_Creating_Mode_Max ]]; then
                return 0
            else
                return 1
            fi
        fi
    else
        Container_Stuck_In_Creating_Mode=0
        return 1
    fi
}

is_pod_stuck_in_pending_state()
{
    arr=$(kubectl get pods -n $qualys_namespace  --selector=name=qualys-container-sensor -o jsonpath='{range.items[*]}{@.spec.nodeName}{"="}{@.status.phase}{","}') 
    for str in ${arr//,/ } ; do
        node=$(echo $str|awk -F= '{printf $1}')
        state=$(echo $str|awk -F= '{printf $2}')
        if [[ 0 -ne `echo $state | grep --ignore-case -c Pending` ]]; then
            if [ ${NodeStateMap[$node]+_} ]; then
                NodeStateMap[$node]=`expr ${NodeStateMap[$node]} + 1`
                if [ ${NodeStateMap[$node]} -eq $Pod_Stuck_In_Pending_State_Max ]; then
                    return 0
                fi
            else
                NodeStateMap[$node]=0
            fi
        else
            NodeStateMap[$node]=0
        fi
    done
    return 1
}

manage_watch_background_process()
{

    line=""
    pipe_status=""
    
    if [[ $# -ne 2 ]]; then
        cleanup
        return
    fi
  
    Rollout_pid=${1}
    Process_to_manage=${2}
 
    while ps "$Rollout_pid" >/dev/null; do 
        # If status of one of the qualys pods is 
        # Failed, then rollback
        # if any of the pods had failed in BackOff, then rollback 
        sleep 10
        pod_status="$(kubectl get pods -n $qualys_namespace  --selector=name=qualys-container-sensor -o jsonpath="{.items[*].status.phase}")"
        if [[ 0 -ne `echo $pod_status | grep --ignore-case -c Failed` || 0 -ne `echo $pod_status | grep --ignore-case -c RunContainerError` ]]; then
	        pod_failure_reason=$(kubectl get pods -n $qualys_namespace --selector=name=qualys-container-sensor -o jsonpath="{.items[*].status.containerStatuses..state..reason}")
            if [[ -z $pod_failure_reason ]]; then
                print "One of the pods has failed in $pod_status."
            else
                print "One of the pods has failed in $pod_status. Reason:$pod_failure_reason"
            fi
            rollback
        elif is_pod_backing_off; then
            print "One of the pods has crashed in backoff, Message : "$(kubectl get pods -n $qualys_namespace --selector=name=qualys-container-sensor -o jsonpath="{.items[*].status.containerStatuses..state..message}")
            rollback
        elif is_pod_stuck_in_creating_state; then
            print "Pod has been stuck in ContainerCreating state for a long time. Aborting rolling update"
            rollback
	    elif is_pod_stuck_in_pending_state; then
	        print "Pod has been stuck in Pending state for a long time. Aborting rolling update"
	        rollback
        else
            read pipe_status <$apipe
            if [[ "$pipe_status" =~ "Added" ]]; then
                read line <$pipe 
                if [ "$line" == $Process_to_manage"_failed" ]; then
                    print "$Process_to_manage has failed "
                    rollback
                elif [ "$line" == $Process_to_manage"_successful" ]; then
                    print "$Process_to_manage is successful "
                    kill_background_processes
                    delete_pipes
                    exit 0
                else
                    # check if it contains _failed or _successful - continue in this case
 		    # Some data in the pipes may be left during rollout
 		    # rollback otherwise
                    if [[  $line =~ "_failed" ||  $line =~ "_successful" ]]; then
 			read pipe_status <$apipe
			if [[ "$pipe_status" =~ "Added" ]]; then
                            read line <$pipe
                            if [ "$line" == $Process_to_manage"_failed" ]; then 
                               print "$Process_to_manage has failed"
                               rollback
                            elif [ "$line" == $Process_to_manage"_successful" ]; then
                               print "$Process_to_manage is successful"
                            fi
			else
			    echo "Unavailable" >$apipe &
                        fi
                    else
                       	print "Not sure what happened to rollout"
                        rollback
                    fi
                fi
            else
                echo "Unavailable" >$apipe &
            fi
        fi
    done

    # read from pipe
    if [ -z $line ]; then
        if read line <$pipe; then
            if [ "$line" == $Process_to_manage"_failed" ]; then
                print "$Process_to_manage has failed"
                rollback
            elif [ "$line" == $Process_to_manage"_successful" ]; then
                print $Process_to_manage" is successful"
            elif [[  $line =~ "_failed" ||  $line =~ "_successful" ]]; then
                # check if it contains _failed or _successful - continue in this case
	            # Some data in the pipes may be left during rollout
 	            # rollback otherwise
    	        if read line <$pipe; then
                    if [ "$line" == $Process_to_manage"_failed" ]; then
                        print $Process_to_manage" has failed"
                        rollback
                    elif [ "$line" == $Process_to_manage"_successful" ]; then
                        print $Process_to_manage" is successful"
                    fi
                else
                    print "Not sure what happened to rollout"
                    rollback
                fi
            else
                print "Not sure what happened to rollout"
                rollback
            fi
        fi
    fi
}

if [ -e $Log_File ]; then
    print ""
    print ""
fi

whitespace="[[:space:]]"

for i in "$@"
do
    if [[ $i =~ $whitespace ]]; then
        i=\"$i\"
    fi

    if [[ $i == "--help" || $i == "-h" ]]; then
        print_usage_and_exit
    fi

    validate $i
    if [[ $? -ne 0 ]]; then
        print_usage_and_exit 
    fi

    if [[ $key == "Registry_Url" ]]; then
        Registry_Url=$val
        Registry_Url_defined=true
    fi
done

# If registry url is not provided, exit with error
if [ "$Registry_Url_defined" = false ]; then
    print "Registry_Url is a mandatory argument"
    print_usage_and_exit
fi

exit_if_no_kubectl

exit_if_no_qualys_ds

# get namespace for qualys-container-sensor
qualys_namespace="kube-system"
qualys_namespace="$(kubectl get ds --all-namespaces --selector=k8s-app=qualys-cs-sensor -o jsonpath="{.items[*].metadata.namespace}" 2>/dev/null)"
if [[ -z $qualys_namespace ]]; then
    print "Unable to get namespace in which qualys-container-sensor daemonset is running, using value "kube-system""
fi

#########------########

# LOAD IMAGE, TAG AND PUSH TO REPO

# check if docker is communicating over tcp
check_dockerd_socket

print "Performing rolling update on qualys-container-sensor daemonset"

Sensor_Image="qualys/sensor"

ImageFile_value="${Script_Directory_Name}qualys-sensor.tar"

if [[ -f "$ImageFile_value" ]] ; then
    print "Loading $Sensor_Image image..."
    QSC_Load="$(${Docker} load -i $ImageFile_value)" & Load_Pid=$!
    while kill -0 $Load_Pid &> /dev/null; do
        printf "▓"
        sleep 0.5
    done
    wait $Load_Pid
    if [[ $? -ne 0 ]]; then
        print "Docker Load Error: Check the file."
        exit 1
    fi
    print " (done)!"
else
    print "Error: $ImageFile_value file does not exist";
    exit 1
fi

if [[ -f "${Script_Directory_Name}"image-id ]] ; then
    QSC_Image="$(cat "${Script_Directory_Name}"image-id)"
else
    print "Qualys Sensor Image ID not known"
    exit 1
fi

# get version info
QSC_Version=""
if [[ -f "${Script_Directory_Name}"version-info ]] ; then
    QSC_Version="$(cat "${Script_Directory_Name}"version-info)"
else
    print "Qualys Sensor Version not known"
    exit 1
fi

# docker tag repo
RepoTag=$Registry_Url/$Sensor_Image:$QSC_Version

QSC_ImageId=${QSC_Image:0:12}

${Docker} tag $QSC_ImageId $RepoTag 2>&1 | adddate 
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    print ""
    print "Docker Tag Error: Failed to tag $Sensor_Image image."
    cleanup
    exit 1
fi

# push to repo
${Docker} push $RepoTag 2>&1 | adddate 
if [[ ${PIPESTATUS[0]}  -ne 0 ]]; then
    print "Docker Push Error: Failed to push $RepoTag image."
    cleanup
    exit 1
else
    print "Successfully pushed $RepoTag image"
fi

############----------------##########

# PERFORM ROLLOUT, MONITOR AND ROLLBACK IF NECESSARY

kubectl apply -f "${Script_Directory_Name}"cssensor-ds.yml 2>&1 | adddate
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    print "Cannot update daemonset"
    cleanup
    exit 1
fi

create_pipes

# do this in a thread
watch_rollout_status &
Rollout_pid=$!

manage_watch_background_process $Rollout_pid Rollout

#########---------############
kill_background_processes
delete_pipes
exit 0

