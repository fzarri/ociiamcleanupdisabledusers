#!/bin/sh
. ./set-local-vars.sh

fn config function $FN_APP_NAME ${PWD##*/} ociIamBaseUrl $OCI_IAM_URL
fn config function $FN_APP_NAME ${PWD##*/} vaultSecretOCIDAppSecret $VAULT_SECRET_OCID_OCI_IAM_APPSECRET
fn config function $FN_APP_NAME ${PWD##*/} ociIamClientId $OCI_IAM_CLIENT_ID
fn config function $FN_APP_NAME ${PWD##*/} ociIamIDAppNameFusion $OCI_IAM_ID_APP_FUSION_SAAS
fn config function $FN_APP_NAME ${PWD##*/} batchSize $FN_BATCH_SIZE
fn config function $FN_APP_NAME ${PWD##*/} maxUserstoDelete $FN_MAX_USERS_TO_DELETE
fn config function $FN_APP_NAME ${PWD##*/} maxWorkers $FN_MAX_WORKERS
fn config function $FN_APP_NAME ${PWD##*/} ociLoggingLogOcid $OCI_LOGGING_LOG_OCID
