#!/usr/bin/env sh

# Script to deploy certificates to Palo Alto Networks PANOS via API
# Note PANOS API KEY and IP address needs to be set prior to running.
# The following variables exported from environment will be used.
# If not set then values previously saved in domain.conf file are used.
#
# Firewall admin with superuser and IP address is required.
#
# REQURED:
#     export PANOS_HOST=""    #Can be a single host, or multiple hosts delimited by a comma or space.
#     export PANOS_USER=""    #User *MUST* have Commit and Import Permissions in XML API for Admin Role
#     export PANOS_PASS=""
#
# EXAMPLE:
#     # You can use any of the following methods to export a host
#     export PANOS_HOST="fw1.mydomain.com"                                         # Single host
#     export PANOS_HOST="fw1.mydomain.com, fw2.mydomain.com, 10.23.1.37"           # Valid multi-host
#     export PANOS_HOST="fw1.mydomain.com fw2.mydomain.com 10.8.8.22"              # Also vaild
#     export PANOS_HOST=",,   fw1.mydomain.com   , 172.15.2.3,fw3.mydomain.com,"   # This works as well! (But WHY?)
#
#     export PANOS_USER="svc_acmeuser"
#     export PANOS_PASS="a089s98qasdjfadfasdsdf"
#
# The script will automatically generate a new API key if
# no key is found, or if a saved key has expired or is invalid.

# This function is to parse the XML response from the firewall
parse_response() {
  type=$2
  if [ "$type" = 'keygen' ]; then
    status=$(echo "$1" | sed 's/^.*\(['\'']\)\([a-z]*\)'\''.*/\2/g')
    if [ "$status" = "success" ]; then
      panos_key=$(echo "$1" | sed 's/^.*\(<key>\)\(.*\)<\/key>.*/\2/g')
      _panos_key=$panos_key
    else
      message="PAN-OS Key could not be set."
    fi
  else
    status=$(echo "$1" | tr -d '\n' | sed 's/^.*"\([a-z]*\)".*/\1/g')
    message=$(echo "$1" | tr -d '\n' | sed 's/.*\(<result>\|<msg>\|<line>\)\([^<]*\).*/\2/g')
    _debug "Firewall message:  $message"
    if [ "$type" = 'keytest' ] && [ "$status" != "success" ]; then
      _debug "****  API Key has EXPIRED or is INVALID ****"
      unset _panos_key
    fi
  fi
  return 0
}

#This function is used to deploy to the firewall
deployer() {
  content=""
  type=$1 # Types are keytest, keygen, cert, key, commit
  panos_url="https://$_panos_host/api/"

  #Test API Key by performing a lookup
  if [ "$type" = 'keytest' ]; then
    _debug "**** Testing saved API Key ****"
    _H1="Content-Type: application/x-www-form-urlencoded"
    # Get Version Info to test key
    content="type=version&key=$_panos_key"
    ## Exclude all scopes for the empty commit
    #_exclude_scope="<policy-and-objects>exclude</policy-and-objects><device-and-network>exclude</device-and-network><shared-object>exclude</shared-object>"
    #content="type=commit&action=partial&key=$_panos_key&cmd=<commit><partial>$_exclude_scope<admin><member>acmekeytest</member></admin></partial></commit>"
  fi

  # Generate API Key
  if [ "$type" = 'keygen' ]; then
    _debug "**** Generating new API Key ****"
    _H1="Content-Type: application/x-www-form-urlencoded"
    content="type=keygen&user=$_panos_user&password=$_panos_pass"
    # content="$content${nl}--$delim${nl}Content-Disposition: form-data; type=\"keygen\"; user=\"$_panos_user\"; password=\"$_panos_pass\"${nl}Content-Type: application/octet-stream${nl}${nl}"
  fi

  # Deploy Cert or Key
  if [ "$type" = 'cert' ] || [ "$type" = 'key' ]; then
    _debug "**** Deploying $type ****"
    #Generate DELIM
    delim="-----MultipartDelimiter$(date "+%s%N")"
    nl="\015\012"
    #Set Header
    export _H1="Content-Type: multipart/form-data; boundary=$delim"
    if [ "$type" = 'cert' ]; then
      panos_url="${panos_url}?type=import"
      content="--$delim${nl}Content-Disposition: form-data; name=\"category\"\r\n\r\ncertificate"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"certificate-name\"\r\n\r\n$_cdomain"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"key\"\r\n\r\n$_panos_key"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"format\"\r\n\r\npem"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"file\"; filename=\"$(basename "$_cfullchain")\"${nl}Content-Type: application/octet-stream${nl}${nl}$(cat "$_cfullchain")"
    fi
    if [ "$type" = 'key' ]; then
      panos_url="${panos_url}?type=import"
      content="--$delim${nl}Content-Disposition: form-data; name=\"category\"\r\n\r\nprivate-key"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"certificate-name\"\r\n\r\n$_cdomain"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"key\"\r\n\r\n$_panos_key"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"format\"\r\n\r\npem"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"passphrase\"\r\n\r\n123456"
      content="$content${nl}--$delim${nl}Content-Disposition: form-data; name=\"file\"; filename=\"$(basename "$_cdomain.key")\"${nl}Content-Type: application/octet-stream${nl}${nl}$(cat "$_ckey")"
    fi
    #Close multipart
    content="$content${nl}--$delim--${nl}${nl}"
    #Convert CRLF
    content=$(printf %b "$content")
  fi

  # Commit changes
  if [ "$type" = 'commit' ]; then
    _debug "**** Committing changes ****"
    export _H1="Content-Type: application/x-www-form-urlencoded"
    #Check for force commit - will commit ALL uncommited changes to the firewall. Use with caution!
    if [ "$FORCE" ]; then
      _debug "Force switch detected.  Committing ALL changes to the firewall."
      cmd=$(printf "%s" "<commit><partial><force><admin><member>$_panos_user</member></admin></force></partial></commit>" | _url_encode)
    else
      _exclude_scope="<policy-and-objects>exclude</policy-and-objects><device-and-network>exclude</device-and-network>"
      cmd=$(printf "%s" "<commit><partial>$_exclude_scope<admin><member>$_panos_user</member></admin></partial></commit>" | _url_encode)
    fi
    content="type=commit&action=partial&key=$_panos_key&cmd=$cmd"
  fi

  response=$(_post "$content" "$panos_url" "" "POST")
  parse_response "$response" "$type"
  # Saving response to variables
  response_status=$status
  _debug response_status "$response_status"
  if [ "$response_status" = "success" ]; then
    _debug "Successfully deployed $type"
    return 0
  else
    _err "Deploy of type $type failed. Try deploying with --debug to troubleshoot."
    _err "$message"
    return 1
  fi
}

# This is the main function that will call the other functions to deploy everything.
panos_deploy() {
  _cdomain=$(echo "$1" | sed 's/*/WILDCARD_/g') #Wildcard Safe Filename
  _ckey="$2"
  _cfullchain="$5"
  _regen_keys=false #Flag to regenerate keys if PANOS_USER or PANOS_PASS changes.
  _old_host=""      #Empty string placeholder for old hosts

  # VALID FILE CHECK
  if [ ! -f "$_ckey" ] || [ ! -f "$_cfullchain" ]; then
    _err "Unable to find a valid key and/or cert.  If this is an ECDSA/ECC cert, use the --ecc flag when deploying."
    return 1
  fi

  ## PANOS_HOST - Can be a single host, or a comma delimited string of multiple hosts
  if [ "$PANOS_HOST" ]; then
    _debug "Detected ENV variable PANOS_HOST. Looking for changes..."
    # Convert ENV variable to  lowercase, sort and remove duplicates, eliminate excessive spaces then put onto new lines
    PANOS_ENV_HOST=$(echo "$PANOS_HOST" | tr '[:upper:]' '[:lower:]' | tr ' ' ',' | tr ',' '\n' | sort -u | tr '\n' ' ' | tr -s ' ' | sed 's/^[ \t]*//g' | tr ' ' '\n')
    unset PANOS_HOST
    #Attempt to load saved variable
    _getdeployconf PANOS_HOST
    _old_host="$PANOS_HOST" #Save the old hosts variable for later cleanup
    if [ -z "$PANOS_HOST" ] || { [ "$PANOS_HOST" ] && [ "$PANOS_ENV_HOST" != "$PANOS_HOST" ]; }; then
      _debug "PANOS_HOST has changed.  Saving changes to disk."
      _savedeployconf PANOS_HOST "$PANOS_ENV_HOST" 1 #Save the new hosts to file
      PANOS_HOST="$PANOS_ENV_HOST"                   #Replace the variable
    else
      _debug "PANOS_HOST is unchanged."
    fi
  else
    _debug "Attempting to load variable PANOS_HOST from file."
    _getdeployconf PANOS_HOST
    _old_host="$PANOS_HOST" #Save the old hosts variable for later cleanup
  fi

  ## PANOS USER
  if [ "$PANOS_USER" ]; then
    _debug "Detected ENV variable PANOS_USER. Looking for changes..."
    #Save PANOS_USER as new variable and unset.  Then attempt to load saved variable.
    PANOS_ENV_USER="$PANOS_USER"
    unset PANOS_USER
    _getdeployconf PANOS_USER
    # Check if saved key exists, or if saved key differs from ENV variable
    if [ -z "$PANOS_USER" ] || { [ "$PANOS_USER" ] && [ "$PANOS_ENV_USER" != "$PANOS_USER" ]; }; then
      _debug "PANOS_USER has changed.  Saving changes to disk."
      _savedeployconf PANOS_USER "$PANOS_ENV_USER" 1
      _regen_keys=true # Regenerate keys if the username changes
      PANOS_USER="$PANOS_ENV_USER"
    else
      _debug "PANOS_USER is unchanged."
    fi
  else
    _debug "Attempting to load variable PANOS_USER from file."
    _getdeployconf PANOS_USER
  fi

  ## PANOS_PASS
  if [ "$PANOS_PASS" ]; then
    _debug "Detected ENV variable PANOS_PASS. Looking for changes..."
    #Save variable as temp
    PANOS_ENV_PASS="$PANOS_PASS"
    unset PANOS_PASS
    #Attempt to load saved variable
    _getdeployconf PANOS_PASS
    if [ -z "$PANOS_PASS" ] || { [ "$PANOS_PASS" ] && [ "$PANOS_ENV_PASS" != "$PANOS_PASS" ]; }; then
      #if [ "$PANOS_ENV_PASS" != "$PANOS_PASS" ]; then
      _debug "PANOS_PASS has changed.  Saving changes to disk."
      _savedeployconf PANOS_PASS "$PANOS_ENV_PASS" 1
      _regen_keys=true #Regenerate keys if the password changes
      PANOS_PASS="$PANOS_ENV_PASS"
    else
      _debug "PANOS_PASS is unchanged."
    fi
  else
    _debug "Attempting to load variable PANOS_PASS from file."
    _getdeployconf PANOS_PASS
  fi

  #Store variables
  _panos_user=$PANOS_USER
  _panos_pass=$PANOS_PASS

  # Check for valid variables
  if [ -z "$PANOS_HOST" ]; then
    _err "No host found. If this is your first time deploying, please set PANOS_HOST in ENV variables. You can delete it after you have successfully deployed the certs."
    return 1
  elif [ -z "$_panos_user" ]; then
    _err "No user found. If this is your first time deploying, please set PANOS_USER in ENV variables. You can delete it after you have successfully deployed the certs."
    return 1
  elif [ -z "$_panos_pass" ]; then
    _err "No password found. If this is your first time deploying, please set PANOS_PASS in ENV variables. You can delete it after you have successfully deployed the certs."
    return 1
  else

    #######################################################
    ### Loop through all current hosts and deploy certs ###
    #######################################################
    _info "**** Deploying certs to hosts ****"
    echo "$PANOS_HOST" | while read -r _panos_host; do
      _debug ""
      _debug "**************************************************"
      _debug "*****  PROCESSING HOST: $_panos_host  *****"
      _debug "**************************************************"

      # Use MD5 to generate unique API key name suffixes, retreive API key from file and store as variable _panos_key
      md5suffix=$(echo "$_panos_host" | md5sum | awk '{print $1}')
      host_key_name="PANOS_KEY_$md5suffix"
      _getdeployconf "$host_key_name"
      eval "_panos_key=\${$host_key_name}"

      # Test API key.  If the key is invalid, the variable _panos_key will be unset.
      if [ "$_panos_key" ]; then
        _debug "**** Testing API KEY ****"
        deployer keytest
      fi

      # Generate a new API key if no valid API key is found, or if _regen_keys is true
      if [ -z "$_panos_key" ] || [ "$_regen_keys" = true ]; then
        _debug "**** Generating new PANOS Host API KEY ****"
        deployer keygen
        _savedeployconf "$host_key_name" "$_panos_key" 1
      fi

      # Confirm that a valid key was generated
      if [ -z "$_panos_key" ]; then
        _err ""
        _err "Unable to generate an API key.  The user and pass may be invalid or not authorized to generate a new key. "
        _err "Please check the PANOS_USER and PANOS_PASS credentials and try again."
        _err "If your credentials are valid, you may need to use the --insecure flag."
        return 1
      else
        deployer cert
        deployer key
        deployer commit
      fi
    done
    _info "**** Finished deploying certs to host(s) ****"

    #########################################################################
    ### Generate a list of deleted hosts and delete orphan keys from conf ###
    #########################################################################
    if [ "$_old_host" ] && [ "$_old_host" != "$PANOS_HOST" ]; then
      _debug "**************************************************"
      _debug "***** Removing orphan keys for deleted hosts *****"
      _debug "**************************************************"
      #Loop through old and new hosts and find orphan hosts so we can delete their associated keys
      echo "$_old_host" | while read -r item; do
        host_to_delete=$(echo "$item" | grep -v "$PANOS_HOST")
        if [ "$host_to_delete" ]; then
          #find the associated key name and clear from domain config file
          md5suffix=$(echo "$host_to_delete" | md5sum | awk '{print $1}')
          host_key_name="SAVED_PANOS_KEY_$md5suffix"
          _debug "*** Deleting saved key for host: $host_to_delete ***"
          _cleardomainconf "$host_key_name"
        fi
      done
      _info "**** Finished removing orphan keys ****"
    fi

  fi
}
