#!/bin/sh
#Master config file for setting up the environment.



export OCI_IAM_URL="https://idcs-ff3747c703314f2a909b6716c5e7bc87.identity.oraclecloud.com"
export VAULT_SECRET_OCID_OCI_IAM_APPSECRET="ocid1.vaultsecret.oc1.eu-frankfurt-1.amaaaaaaupfargiad4etu34n5uejzyapzytbx5bzzuhs756vgbz725vtnomq"
export OCI_IAM_CLIENT_ID="4d0bba2fde6d41a6906fb0ec20b39554"
export OCI_IAM_ID_APP_FUSION_SAAS="xxxxxxxxx"
export FN_MAX_USERS_TO_DELETE="1"
export FN_BATCH_SIZE="100"
export FN_MAX_WORKERS="4"
export FN_APP_NAME="oci-iam-delete-disabled-users"
