# Palo Alto Networks - Cloud Security Summit 2019 - AUTOMATICALLY SECURING DEPLOYMENTS IN THE CLOUD
_by James Holland and Scott McAndrew_

This template auto deploys an environment in Google Cloud Platform (GCP) which is secured by a Palo Alto Networks Next Generation Firewall.

_This readme is still a work in progress_

## Components

There are a number of components involved in building the environment:

* GCP account and credentials (API access).
* Terraform: responsible for building the environment, maintaining state, and eventually destruction.
* Ansible: responsible for provisioning (configuring) the Next Generation Firewall.
* Nix environment: Recommend to be run in a container, which is how this workflow was intended/designed.
  * Maintain the depencies for the components as described in this section.
  * Storing environment variables (more on this later).
  * Running Bash scripts.
* *If* triggering remotely (which is how this project was intended), then a system capable of generating an API and passing variables over. We used ServiceNow in this project. A free developer account can be set up at https://developer.servicenow.com

The following section will discuss the prerequisites required to run this project.

### Prerequisites

Terraform State

* Update backend.tf to your own S3 bucket.
* Alternatively delete backend.tf and you can have local state for dev. Then you won't need the AWS credentials at all.

This project heavily relies on environment variables. There are a number of reasons for this:

* Avoids the use of hard-coded credentials in the source code. This is especially effective when run on a container, since such sensitive information will be destroyed when the dpeloyment job is complete.
* Ensures the environment components are named and identified dynamically.
* As part of ServiceNow (or other API-aware service management system) integration - variables are passed to customise the environment. This project also has a hook back to ServiceNow to update the request ticket with information generated in the output (e.g. IP addresses).

Terraform architecture is out of scope for this project README, but one important point which needs to be made, is how it handles variables. Once a variable is declared, the value can be: 

* Explicity set within the variable declaration. This is not scalable but can be useful for static values (*not* for credentials/API keys!!).
* No explicit declaration, but rather a default value set. Useful for fallback values such as Public Cloud region or naming conventions.
* Variable values set within terraform.tfvars - similar to explicitly defining in the variable declaration, but simply de-coupled. This has the same issue in regards to hard-coded credentials. This can still be useful to track non-sensitive variables and provides a single place to configure/update. Using the argument -var-file="variablesFile.tfvars" can allow one to build and reference different variable files.
* *Environment Variables*: Terraform will automatically check for variable values in the form "TF_VAR_variableName" as long as they are defined with no value set. This is our preferred way to coding credentials into the project, such as AWS and GCP keys. The added advantage of this feature is it allows us to set dynamic variable values on the fly. In this project we are doing so from ServiceNow - attributes such as the request number and user details.

#### Required Variables

The following are the variables which have been set on GitLab under Project > Settings > CI/CD > Environment Variables. These will need to be set individually for each version of this project.

* AWS_ACCESS_KEY_ID             -- Credentials for AWS - used in Terraform remote state - S3
* AWS_SECRET_ACCESS_KEY         -- Credentials for AWS - used in Terraform remote state - S3
* TF_VAR_email_key              -- Email API key
* TF_VAR_gcp_credentials        -- Credentials for GCP - where the environment is being created
* TF_VAR_gcp_ssh_public_key     -- Public key name for GCP
* TF_VAR_panos_api_key          -- API key for Palo Alto Networks Next Generation Firewall - to allow API configuration
* TF_VAR_sms_key                -- SMS service API key
* TF_VAR_sn_api_user            -- ServiceNow user which has API rights - this is to update the request based on outputs from Terraform
* TF_VAR_sn_api_user_pw         -- ServiceNow API user password
* TF_VAR_user_password          -- User password which will be set on the firewall

The following are additional variables which we are passing dynamically:
* TF_VAR_subnetOctet            -- To specify the subnets of the deployment
* TF_VAR_requestNumber          -- Unique number of the ServiceNow request
* TF_VAR_requested_for_email    -- Requesting user's email address
* TF_VAR_requested_for_mobile   -- Requesting user's mobile phone number (for SMS alert)
* TF_VAR_cloudPlatform          -- This varaible is collected on the request. Since this particular project is GCP, we build on GCP. Functionality will be added soon which can build on AWS and Azure.
* TF_VAR_deploymentArea         -- On ServiceNow - choices are Prod, Dev and Test. Future feature to build different environments based on this choice.
* TF_VAR_devWorkflow            -- On ServiceNow - choices are Full App Stack, Big Data Analytics and Database. Future feature to build different environments based on this choice.
* TF_VAR_projectName            -- Name of project on ServiceNow for tracking and audit purposes. This is also used to generate the MotD.
* TF_VAR_tf_workspaceName       -- This variable is generated on ServiceNow, using contacenation taking unique values. This ensures Terraform works within unique workspaces for each deployment.
* tfCommand                     -- This variable is passed by ServiceNow to dictate whether the job will be terraform apply or destroy. The choice is based on the action of the request. Once approved by manager - apply. If termination request is received, a destroy action will be passed.
* tf_workspaceAction            -- This variable is passed by ServiceNow to dictate whether we will be creating a new workspace (new deployments) or switching to an existing one (changes/destroy).

#### GitLab CI/CD

A tutorial of GitLab's CI/CD capabilities are out of scope of this readme. However we will provide an overview of how it is used in this project.

Firstly, a file named .gitlabci-yml must be created in the project root folder. This effectively enables CI/CD on the project. Being YML format it is relatively easy to understand and configure. These are the key components of this project's YML file:

* Set Docker image to run the workflow. We have branched https://github.com/ajoldham/pantools and uploaded to Docker Hub. GitLab automatically pulls this image on pipeline creation. The image contains all the dependencies we need, including Terraform and Ansible.
* Before script performs some Terraform housekeeping and switches/creates the unique workspace.
* The actions then are simply - run the appropriate Terraform command.

## Known Limitations / Issues


## Authors

* James Holland. Twitter: @jamesholland_uk ; GitHub: jamesholland-uk
* Scott McAndrew: Twitter: @smcandrew_cyber ; GitHub: scottymcandrew
