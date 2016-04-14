#!/bin/bash

user=admin
pass=secret_password_here
log=log.log

# Generic function for logging
function log() {
    echo `date "+%D %T - "` "${@}" >> ${log}
}

# Will call log() with a INFO prefix
function info() {
    log "INFO - ${@}"
}

# Will call log() with a DEBUG prefix
function debug() {
    log "DEBUG - ${@}"
}

# Will call log() with a ERROR prefix
function error() {
    log "ERROR - ${@}"
}

# Reads a line from AMI (stdin), will strip \r
function readLine() {
    local line=""
    read line
    line=`echo ${line} | tr -d "\r"`
    echo ${line}
}

# Reads a full PDU from asterisk. Since Asterisk messages
# ends with a \r\n\r\n, and we use "read" to read line by
# line, this will translate to an empty line delimiting
# PDUs. So read up to an empty line, and return whatever
# read.
function readPdu() {
    local pdu=""
    local complete=0
    while [ ${complete} -eq "0" ]; do
        line=`readLine`
	    debug "Line: ${line}"
        # End Of Message detected
        if [[ -z ${line} ]]; then
            complete=1
        else
            # Concat line read
           pdu=`printf "${pdu}\\\n${line}"`
        fi
    done
    echo ${pdu}
}

# Performs a Login action. Will terminate with error code 255 if
# the asterisk ami welcome message is not found.
# Asterisk Call Manager/1.0
function login() {
    local welcome=`readLine`
#   debug "Welcome: ${welcome}"
    if [[ ${welcome} != "Asterisk Call Manager/1.0" ]]; then
        error "Invalid peer. Not AMI."
        exit 255
    fi
    printf "Action: Login\r\nUsername: ${user}\r\nSecret: ${pass}\r\nEvents: on\r\n\r\n"
    local response=`readPdu`
    if [[ ! ${response} =~ Success ]]; then
        error "Could not login: ${response}"
        exit 254
    fi

#    printf "ACTION: RptStatus\r\nCOMMAND: RptStat\r\nNODE: 2154\r\nActionID: 1111\r\n\r\n"
#    local response=`rptstat`
#    debug "RptStat: ${rptstat}"

#    printf "ACTION: RptStatus\r\nCOMMAND: NodeStat\r\nNODE: 2154\r\nActionID: 2222\r\n\r\n"
#    local response=`nodestat`
#    debug "NodeStat: ${nodestat}"

#    printf "ACTION: RptStatus\r\nCOMMAND: XStat\r\nNODE: 2154\r\nActionID: 3333\r\n\r\n"
#    local response=`xststat`
#    debug "XStat: ${xstat}"

#    printf "ACTION: RptStatus\r\nCOMMAND: SawStat\r\nNODE: 2154\r\nActionID: 4444\r\n\r\n"
#    local response=`sawstat`
#    debug "SawStat: ${sawstat}"

# {"RptStat",MGRCMD_RPTSTAT},
# {"NodeStat",MGRCMD_NODESTAT},
# {"XStat",MGRCMD_XSTAT},
# {"SawStat",MGRCMD_SAWSTAT},


# CHANNELS=`/bin/echo -e "et: ${AMIPASS}\r\nEvents: off\r\n\r\nAction: CoreShowChannels\r\n\r\nAction: Logoff\r\n\r\n" `


}

# Do login.
login

# Main reading loop.
while [ true ]; do
    pdu=`readPdu`
#  debug "${pdu}"
    regex="Event: *"
    if [[ $pdu =~ $regex ]]; then
        eventName=`echo ${pdu} | cut -d' ' -f2`
        case ${eventName} in
            DTMF)
                info DTMF
            ;;
            VarSet)
            ;;
            Newchannel)
		info Newchannel
            ;;
            Hangup)
            ;;
            RPT_LINKS)
                info RPT_LINKS
            ;;
            RPT_RXKEYED)
                info RPT_RXKEYED
            ;;
            RPT_ETXKEYED)
                info RPT_ETXKEYED
            ;;
            RPT_TXKEYED)
                info RPT_TXKEYED
            ;;
            RPT_ALINKS)
                info RPT_ALINKS
            ;;
            RPT_NUMALINKS)
                info RPT_NUMALINKS
            ;;
            RPT_NUMLINKS)
                info RPT_NUMLINKS
            ;;
            *)
                info "=== Unhandled event: ${eventName} ==="
            ;;
        esac
    else
        info "Response: ${pdu}"
    fi
done

# allmon.inc.php:    fwrite($fp,"ACTION: LOGIN\r\nUSERNAME: $user\r\nSECRET: $password\r\nEVENTS: 0\r\nActionID: $actionID\r\
# connect.php:if ((@fwrite($fp,"ACTION: COMMAND\r\nCOMMAND: rpt cmd $localnode ilink $ilink $remotenode\r\nActionID: $actionI
# controlserver.php:if ((@fwrite($fp,"ACTION: COMMAND\r\nCOMMAND: $cmdString\r\nActionID: $actionID\r\n\r\n")) > 0 ) {
# server.php:fwrite($fp, "ACTION: Logoff\r\n\r\n");
# server.php:    if ((fwrite($fp,"ACTION: RptStatus\r\nCOMMAND: XStat\r\nNODE: $node\r\nActionID: $actionID\r\n\r\n")) !== FA
# server.php:    if ((fwrite($fp,"ACTION: RptStatus\r\nCOMMAND: SawStat\r\nNODE: $node\r\nActionID: $actionID\r\n\r\n")) !==
# voterserver.php:    if ((@fwrite($fp,"ACTION: VoterStatus\r\nActionID: $actionID\r\n\r\n")) > 0) {
# RPT_NUMLINKS
