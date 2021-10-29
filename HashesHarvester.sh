#!/usr/bin/env bash

log()  { echo -e "\x1b[1m[\x1b[93mLOG-\x1b[0m\x1b[1m]\x1b[0m ${1}"; }
info() { echo -e "\x1b[1m[\x1b[92mINFO\x1b[0m\x1b[1m]\x1b[0m ${1}"; }
warn() { echo -e "\x1b[1m[\x1b[91mWARN\x1b[0m\x1b[1m]\x1b[0m ${1}"; }

#===============================================================================


extract_ntlm_hashes() {
    local MEMORYFILE=${1}
    log "Searching matching profiles ..."
    local PROFILES=$(volatility -f ${MEMORYFILE} imageinfo 2>/dev/null | grep "Suggested Profile" | awk '{split($0,a,":"); print a[2]}')
    if [[ ${PROFILES} != "" ]]; then
        info "Found matching profiles :"
        echo "     | ${PROFILES}"
        PROFILES=$(echo "${PROFILES}" | sed "s/,//g")
        PSELECTED=$(set -- ${PROFILES}; echo $1)
        log "Selecting profile : ${PSELECTED}"
        log "Extracting hivelist ..."
        local HIVES=$(volatility -f ${MEMORYFILE} --profile=${PSELECTED} hivelist 2>/dev/null)

        SYSTEM_VIRTUALOFFSET=$(echo "${HIVES}" | grep "\SYSTEM" | awk '{split($0,a," "); print a[1]}')
        if [[ ${SYSTEM_VIRTUALOFFSET} == "" ]]; then warn "Could not find SYSTEM in hivelist"; exit 1;  fi
        info "Found SYSTEM at virtual offset \x1b[96m${SYSTEM_VIRTUALOFFSET}\x1b[0m in hivelist !"

        SAM_VIRTUALOFFSET=$(echo "${HIVES}" | grep "\SAM" | awk '{split($0,a," "); print a[1]}')
        if [[ ${SAM_VIRTUALOFFSET} == "" ]]; then warn "Could not find SAM in hivelist"; exit 1;        fi
        info "Found SAM    at virtual offset \x1b[96m${SAM_VIRTUALOFFSET}\x1b[0m in hivelist !"

        log "Extracting hashes ..."
        local HASHES=$(volatility -f ${MEMORYFILE} --profile=${PSELECTED} hashdump -y ${SYSTEM_VIRTUALOFFSET} -s ${SAM_VIRTUALOFFSET} 2>/dev/null)
        echo "${HASHES}" | sed 's/^/     | /'
        info "Hashes saved to \x1b[1mhashes.txt\x1b[0m"
        info "Extraction complete !"
    else
        warn "No matching profiles found."
        exit 1
    fi

}

header() {
    echo "Hashes-Harvester: Automatically extracts hashes from Windows memory dumps."
}

usage() {
    echo "Usage : ${1} MEMORYFILE"
}

#===============================================================================

if [[ $# -ne 1 ]]; then
    header
    usage ${0}
else
    header
    MEMORYFILE=${1}
    if [[ $(which volatility) != "" ]]; then
        extract_ntlm_hashes ${MEMORYFILE}
    else
        warn
        exit 1
    fi
fi
