#!/bin/sh

/google-cloud-sdk/bin/gcloud --no-user-output-enabled auth activate-service-account --key-file=gcp_compute_key_svc_cloud-automation.json
/google-cloud-sdk/bin/gcloud --no-user-output-enabled config set project cloud-automation-demo

mgmt_ip=`/google-cloud-sdk/bin/gcloud compute instances list | grep fw- | grep -i $1 | awk -F"[ ,]+" '{print $8}'`
apikey=`cat fw-api-key`

ansible-playbook ngfw_switch.yml --extra-vars "mgmt_ip=$mgmt_ip apikey=$apikey switch_value=on"
