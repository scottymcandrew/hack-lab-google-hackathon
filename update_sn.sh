#!/bin/bash

##If using ServiceNow, this command hooks back to update the table with some outputs. Replace the dev URL with your own.
#curl "https://devXXXXXX.service-now.com/api/now/table/x_318349_devsecops_table/$TF_VAR_requestSysID" --request PUT --header "Accept:application/json" --header "Content-Type:application/json" --data "{\"u_web_server_ip\":'\"$1\"',\"u_fw_url\":'\"https://$2\"',\"state\":\"20\"}" --user $TF_VAR_sn_api_user:$TF_VAR_sn_api_user_pw