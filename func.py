################################################################################
# Copyright (c) 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License
# (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License
# 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose
# either license.

# This code is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND.
# It is intended as a demonstration and should not be used for any other purposes.

#
# Note: This code is a very dumb and is intended as a simple example of how to
# make SCIM calls. It has little to no sanity checking and will throw whatever
# exceptions the underlying layer throws when it encounters a problem
#
# The big exception to the above is in the bulk call.
# Which is somehow even worse. Specifically it doesn't bother to tell you if
# any of the requests inside the bulk request failed. It just happily continues
#
# You have been warned!
#
################################################################################

import io
import urllib.parse
import json
import base64
import oci
import logging
import hashlib
import sys
import string
import random
import datetime
import uuid

# this is for our worker thread pool
import concurrent.futures


from IAMClient import IAMClient


from fdk import response


def init_secret_client():
    try:
        rps = oci.auth.signers.get_resource_principals_signer()
        secret_client = oci.secrets.SecretsClient({}, signer=rps)
    except Exception as e:
        logging.getLogger().error("Init secret client Error: %s", e)
    else:
        logging.getLogger().debug("Secret client initialized")
    return secret_client


# Get Key from OCI Vault Secret
def get_secret(client, secret_ocid):

    logging.getLogger().debug("Start - Get App Secret form OCI Vault Secret")
    # Get Key from OCI Vault Secret
    try:
        response = client.get_secret_bundle(secret_ocid)
        base64_Secret_content = response.data.secret_bundle_content.content
        base64_secret_bytes = base64_Secret_content.encode("ascii")
        base64_message_bytes = base64.b64decode(base64_secret_bytes)
        secret_content = base64_message_bytes.decode("ascii")

    except Exception as ex:
        logging.getLogger().error("Failed to retrieve the OCI Secret content: %s", ex)
        raise
    logging.getLogger().debug("End - Get App Secret form OCI Vault Secret")
    return secret_content
    
def search_filter(ociIamIDAppNameFusion, filter, searchsize, startIndex):

    logging.getLogger().debug("Constructing search filter...")
    
    #filter = "active eq false"
    filter = 'urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User:syncedFromApp.value eq "{}" and active eq false'.format(ociIamIDAppNameFusion) 

    logging.getLogger().debug("Filter Search Users: {}".format(filter))
    # my search options
    args = {
         "sortBy": "id",
         "attributes": "id",
         "filter": filter,
         "count": searchsize,
         "startIndex": str(startIndex)
         }
    
    logging.getLogger().debug("Return Filter: {}".format(args))
    return args
    

def handler(ctx, data: io.BytesIO = None):
    #Valid Value Log Level


    #Set Logging level
    #logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger().setLevel(logging.INFO)
   
    #oci.base_client.is_http_log_enabled(True)
    oci.base_client.is_http_log_enabled(False)
    
    # SEARCHSIZE is how many we should ask for in each search
    SEARCHSIZE = 1000
    
    try:
        logging.getLogger().info("function start")

        logging.getLogger().info("get configuration parameter")
        cfg = dict(ctx.Config())
        vaultSecretOCIDAppSecret = cfg["vaultSecretOCIDAppSecret"]
        logging.getLogger().debug(
            "Vault Secret ocid for OCI IAM App Secret: " + vaultSecretOCIDAppSecret
        )
        clientId = cfg["ociIamClientId"]
        logging.getLogger().debug("OCI IAM Auth ClientId: " + clientId)
        ociIamBaseUrl = cfg["ociIamBaseUrl"]
        logging.getLogger().debug("OCI IAM Base Url: " + ociIamBaseUrl)
        maxUserstoDelete = cfg["maxUserstoDelete"]
        logging.getLogger().debug("Max number of users to delete: " + maxUserstoDelete)
        batchSize = cfg["batchSize"]
        logging.getLogger().debug(
            "Number of deletes we should do in a SCIM BULK call: " + batchSize
        )
        maxWorkers = cfg["maxWorkers"]
        logging.getLogger().debug(
            "Max Workers creates the thread pool that we will use to do the deletes asynchronously: "
            + maxWorkers
        )
        ociIamIDAppNameFusion = cfg["ociIamIDAppNameFusion"]
        logging.getLogger().info(
            "OCI IAM ID App SaaS Fusion = " + ociIamIDAppNameFusion
        )
        
        
        # BATCHSIZE is the number of deletes we should do in a SCIM BULK call
        BATCHSIZE = int(batchSize)

        # MAXUSERSTODELETE is the max number of users to delete
        MAXUSERSTODELETE = int(maxUserstoDelete)

        logging.getLogger().info("Start Execution")
        # Step 1: Initializing Secret Client
        logging.getLogger().debug("initializing secret client")
        secret_client = init_secret_client()
        logging.getLogger().debug("secret client obtained with Instance Principal")

        # Step 2: Get Secret from OCI Vault Secret
        logging.getLogger().debug("get App Secret from OCI Vault Secret")
        clientSecret = get_secret(secret_client, vaultSecretOCIDAppSecret)
        logging.getLogger().debug("secret client obtained with Instance Principal")

        # Step 3: Instance IAMClient
        logging.getLogger().debug("Inizialiting IAMClient")
        iam = IAMClient(ociIamBaseUrl, clientId, clientSecret)

        # start with an empty array
        reqs = []

        futures = []
        # and this actually creates the thread pool that we will use to do the deletes asynchronously
        max_workers = int(maxWorkers)

        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

        startIndex=1
        logging.getLogger().debug("Filter Search Users: {}".format(filter))
        args = search_filter(ociIamIDAppNameFusion, filter, SEARCHSIZE, startIndex)
        logging.getLogger().debug("Search Users in OCI IAM")
        resultUsers = iam.GetUsers(args)
        totalUsersReturn = resultUsers["totalResults"]
        logging.getLogger().debug("Total of users return: {}".format(totalUsersReturn))
        logging.getLogger().info("Total number of users to delete in OCI IAM: {}".format(totalUsersReturn))
        countusers = 0
        usersdeleteLogEntries = []
        
        if totalUsersReturn > 0:
            users = resultUsers["Resources"]
            while startIndex < totalUsersReturn and startIndex < MAXUSERSTODELETE:
                
                startIndex = startIndex + SEARCHSIZE
                logging.getLogger().debug("Paging OCI IAM Users API Seach, StartIndex {}".format(startIndex))
                
                args = search_filter(ociIamIDAppNameFusion, filter, SEARCHSIZE, startIndex)
                
                resultUsers = iam.GetUsers(args)
                
                users += resultUsers["Resources"]     
        

            for user in users:
                if countusers == MAXUSERSTODELETE:
                    logging.getLogger().info(
                        "Limit max Users to delete: " + str(MAXUSERSTODELETE)
                    )
                    break  # max users

                logging.getLogger().info(
                    "User {} -> {}".format(user["userName"], user["id"])
                ) 

                                         
                
                # create a DELETE request for the user id (note: not username - this is the value of the id attribute of the user object)
                reqs += [
                    {
                        "method": "DELETE",
                        "path": "/Users/" + user["id"] + "?forceDelete=true",
                        "bulkId": "".join(random.choices(string.ascii_lowercase, k=10)),
                    }
                ]

                if BATCHSIZE == len(reqs):
                    logging.getLogger().info(
                        "Queuing {} users for deletion".format(len(reqs))
                    )
                    futures.append(executor.submit(iam.bulkRequest, reqs))
                    logging.getLogger().info("Queued.")
                    reqs = []
                countusers += 1
                
            
            
  
            logging.getLogger().info("Queuing last {} users for deletion".format(len(reqs)))
            futures.append(executor.submit(iam.bulkRequest, reqs))
            logging.getLogger().info("Queued.")

            logging.info("Waiting for worker pool to complete.")
            for future in concurrent.futures.as_completed(futures):
                if future.done():
                    logging.getLogger().info("Future is done")
                elif future.cancelled():
                    logging.getLogger().info("Future is cancelled")
                # this shouldn't happen but just in case
                else:
                    logging.error("Future did something weird")
            
            logging.getLogger().info("Deleted Users: {}".format(countusers))
            
            
            
        else:
            logging.getLogger().info("No Users to Delete")
        
        logging.getLogger().info("function end")
        return response.Response(
            ctx,
            response_data=json.dumps({"status": "ok"}),
            headers={"Content-Type": "application/json"},
        )
    except (Exception, ValueError) as ex:
        logging.getLogger().error("error during routine: " + str(ex))
        pass
        return response.Response(
            ctx, status_code=401, response_data=json.dumps({"error": "exception"})
        )

