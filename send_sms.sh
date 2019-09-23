#!/bin/bash

# $1 User mobile phone number 
# $2 SE mobile phone number
# $3 Firewall mgmt IP
# $4 Firewall admin password
# $5 SMS API key

# SMS to user
curl -X POST https://textbelt.com/text --data-urlencode phone=$2 --data-urlencode message="Hi, your deployment is done. Here's your firewall: $3 Login with username user and password $4" -d key=$5

# SMS to SE
curl -X POST https://textbelt.com/text --data-urlencode phone=$1 --data-urlencode message="Hi, your deployment is done. Here's your firewall: $3 Login with username user and password $4" -d key=$5