#!/bin/bash

# $1 SE email address
# $2 Email service API key
# $3 Firewall mgmt IP
# $4 Firewall admin password
# $5 Web applications IP (firewall's untrust interface IP)
# $6 Attacker machine IP
# $7 User email address
# $8 Request number

user_message_txt=$'Hi,<br><br>Thanks for using the cloud automation demo.<br><br>Your Java web application can be found <a href=http://'"$5"':8080/struts2_2.3.15.1-showcase/showcase.action>here</a> and your PHP web application can be found <a href=http://'"$5"'>here</a>.<br><br>Your firewall was deployed to https://'"$3"' <br><br>Login with username user and password '"$4"'<br><br>Kind regards,<br>Palo Alto Networks<br><br><br><br><img src=jamoi.co.uk/gcp-process.png width=75% height=75%>'

se_message_txt=$'<br>'"$8"'<br><b>DEPLOYMENT</b><br><br><a href=http://'"$5"':8080/struts2_2.3.15.1-showcase/showcase.action>Java web application</a><br><br><a href=http://'"$5"'>PHP web application</a><br><br><a href=https://'"$3"'>Newly created firewall</a> - Username user - Password '"$4"'<br><br><a href=https://rama.panw.uk>Panorama</a><br><br><a href=https://app.redlock.io/>RedLock</a><br><br><a href=https://autocloud-traps.traps.paloaltonetworks.com>Traps TMS</a><br><br><img src=jamoi.co.uk/gcp-process.png width=75% height=75%><br><br><b>ATTACKER</b><br><br><a href=http://'"$6"':4200>Attacker Metasploit Console</a> Username user and password '"$4"'<br><br><a href=http://'"$5"'?uoGSo[]=%3Cscript%3Ealert(%E2%80%98BreakingPoint%E2%80%99)%3C/script%3E>Generic XSS Attack</a><br><br><a href=http://'"$5"'/graph.php?current_language=/../../../../../../../../etc/passwd.&module=Accounts&action=Import&parenttab=Support%5D>Generic Traversal and /etc/passwd Access</a><br><br><a href=http://'"$5"':4200>Attacker Web Server Console</a> Username user and password '"$4"'<br><br><br><br><b>TURN OFF NGFW (Rely on Cloud Native Security</b><br><br><a href=http://autocloud-ngfw-switch.panw.uk:4200>Console to turn off NGFW with Ansible playbook</a> Username switcher and password Automation123<br><br>'


# Email for the user on completion
curl -s --user 'api:'"$2"'' https://api.mailgun.net/v3/demo.panw.co.uk/messages -F from='Palo Alto Networks <demo@demo.panw.co.uk>' -F to=$7 -F subject='Cloud Automation Demo - Palo Alto Networks' -F html=' '"$user_message_txt"' '

# Email to send to the SE on completion
curl -s --user 'api:'"$2"'' https://api.mailgun.net/v3/demo.panw.co.uk/messages -F from='Cloud Automation Demo <demo@demo.panw.co.uk>' -F to=$1 -F to=panw.uk@gmail.com -F subject='Cloud Automation Demo and Attacks Ready '"$8"'' -F html=' '"$se_message_txt"' '

# Email to monitor demo usage on completion
curl -s --user 'api:'"$2"'' https://api.mailgun.net/v3/demo.panw.co.uk/messages -F from='Palo Alto Networks <demo@demo.panw.co.uk>' -F to=jholland@paloaltonetworks.com -F to=smcandrew@paloaltonetworks.com -F subject='ServiceNow GCP HackLab Demo Used by Someone - Completed '"$8"'' -F html=' '"======<br>USER EMAIL<br>======<br> $user_message_txt ======<br>SE EMAIL<br>======<br> $se_message_txt"' '