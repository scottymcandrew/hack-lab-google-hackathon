#!/bin/sh

/google-cloud-sdk/bin/gcloud --no-user-output-enabled auth activate-service-account --key-file=gcp_compute_key_svc_cloud-automation.json
/google-cloud-sdk/bin/gcloud --no-user-output-enabled config set project cloud-automation-demo

mgmt_ip=`/google-cloud-sdk/bin/gcloud compute instances list | grep fw- | grep $1 | awk -F"[ ,]+" '{print $8}'`
untrust_ip=`/google-cloud-sdk/bin/gcloud compute instances list | grep fw- | grep $1 | awk -F"[ ,]+" '{print $9}'`
kali_ip=`/google-cloud-sdk/bin/gcloud compute instances list | grep kali- | grep $1 | awk '{print $5}'`

#echo "fw-mgmt: ${mgmt_ip}"
#echo "fw-ext: ${untrust_ip}"
#echo "kali: ${kali_ip}"

echo ""
echo "Firewall Management                      https://${mgmt_ip}"
echo "Panorama Management                      https://rama.panw.uk"
echo "Metasploit Console                       http://${kali_ip}:4200"
echo "Java Web App                             http://${untrust_ip}:8080/struts2_2.3.15.1-showcase/showcase.action"
echo "PHP Web App                              http://${untrust_ip}"
echo "Generic XSS Attack                       http://${untrust_ip}?uoGSo[]=%3Cscript%3Ealert(%E2%80%98BreakingPoint%E2%80%99)%3C/script%3E"
echo "Generic Traversal and /etc/passwd Access http://${untrust_ip}/graph.php?current_language=/../../../../../../../../etc/passwd.&module=Accounts&action=Import&parenttab=Support%5D"
echo "Web Server Console                       http://${untrust_ip}:4200"
echo ""
