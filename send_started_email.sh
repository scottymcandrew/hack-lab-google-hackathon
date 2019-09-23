#!/bin/bash

# $1 Email service API key
# $2 SE email address
# $3 Request number

message_txt=$'New demo kicked off - '"$3"''

se_message_txt=$'<br>'"$3"'<br><b>OBSERVE DEPLOYMENT</b><br><br><a href=https://gitlab.com/james-scott-automation/gcp-cloud-summit/pipelines>CI/CD Pipeline Runner (Observe Terraform, Ansible, etc)</a><br><br><a href=https://console.cloud.google.com/compute/instances?authuser=0&project=cloud-automation-demo>GCP Tenant</a><br><br><a href=https://console.cloud.google.com/home/activity?authuser=0&project=cloud-automation-demo>GCP Activity Log</a><br><br><a href=https://www.youtube.com/watch?v=DvLN-VH_xoo&feature=youtu.be>Video of manual process</a><br><br><img src=jamoi.co.uk/gcp-topology.png width=75% height=75%><br><br>'

# Email to send to the SE on start of deployment
curl -s --user 'api:'"$1"'' https://api.mailgun.net/v3/demo.panw.co.uk/messages -F from='Palo Alto Networks <demo@demo.panw.co.uk>' -F to=$2 -F to=panw.uk@gmail.com -F subject='Cloud Automation Demo Started '"$3"'' -F html=' '"$se_message_txt"' '

# Email to monitor demo usage on start of deployment
curl -s --user 'api:'"$1"'' https://api.mailgun.net/v3/demo.panw.co.uk/messages -F from='Palo Alto Networks <demo@demo.panw.co.uk>' -F to=smcandrew@paloaltonetworks.com -F to=jholland@paloaltonetworks.com -F subject='ServiceNow GCP HackLab Demo Used by Someone - Started '"$3"'' -F html=' '"$message_txt"' '
