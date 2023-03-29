
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

import json
import logging

# OAuth stuff
import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc6749.errors import OAuth2Error
import urllib.parse



class IAMClient:
    class Error(Exception):
        """Base class for other exceptions"""
        pass

    class NoResults(Error):
        """Raised when the search returns no results"""
        pass

    ociIamUrl = None
    clientID = None
    clientSecret = None

    oauthClient = None

    def __init__(self, ociIamURL, clientID, clientSecret):
       
        

        # TODO: add checks

        logging.getLogger().debug("Initializing OCI IAM client with the following params:")
        logging.getLogger().debug("OCIIAM URL: {}".format(ociIamURL))
        logging.getLogger().debug("Client ID: {}".format(clientID))
        logging.getLogger().debug("Client Secret: {}".format(clientSecret))

        self.ociIamUrl = ociIamURL
        self.clientID = clientID
        self.clientSecret = clientSecret

        token_endpoint = ociIamURL + '/oauth2/v1/token'
        scope="urn:opc:idm:__myscopes__"

        try:

            self.oauthClient = OAuth2Session(
                                            clientID, 
                                            clientSecret, 
                                            scope=scope, 
                                            token_endpoint=token_endpoint
                                            ) 

            token = self.oauthClient.fetch_token()
            logging.getLogger().debug( "Access Token: {}".format(token.get("access_token")))
        except OAuth2Error as err:
            logging.getLogger().error("Error generate OAuth2 Session: %s", err)
            raise    
        return
   
    def GetUsers(self, params):
        logging.getLogger().debug("GetUsers() called")

        uri = "/admin/v1/Users"
        if params:
            uri += "?" + urllib.parse.urlencode( params )
        results = self._sendRequest( "GET", uri, None )
        return results

        

    def GetApps(self, params):
        logging.getLogger().debug("GetApps() called")
        
        uri = "/admin/v1/Apps"
        if params:
            uri += "?" + urllib.parse.urlencode( params )
        return self._sendRequest( "GET", uri, None )
        


    def GetMyAppID(self):
        logging.getLogger().debug("GetMyAppID() called")
        result = self.GetApps( {
                                "filter" : "name eq \"" + self.clientID + "\"",
                                "attributes" : "id"
                               })
        id = result["Resources"][0]["id"]
        logging.getLogger().info( "Got ID for app as {}".format(id) )
        return id
    
    def GetAppID(self, nameapp):
        logging.getLogger().debug("GetMyAppID() called")
        result = self.GetApps( {
                                "filter" : "displayName eq \"" + displayNameApp + "\"",
                                "attributes" : "id"
                               })
        id = result["Resources"][0]["id"]
        logging.getLogger().debug( "Got ID for app as {}".format(id) )
        return id

    def CreateApp(self, clientName, redirectUris):
        logging.getLogger().debug("CreateApp() called")
        appPayload = {
            "displayName": clientName,
            "redirectUris": redirectUris,

            # the rest of these are more or less "fixed" values needed for an OAuth app
            "allUrlSchemesAllowed": True,
            "description": "created via DCR PoC code",
            "clientType": "confidential",
            "allowedGrants": [
                "authorization_code"
            ],
            "isOAuthClient": True,
            "basedOnTemplate": {
                "value": "CustomWebAppTemplateId"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:oracle:idcs:App"
            ]
        }

        createResponse = self._sendRequest( "POST", "/admin/v1/Apps", appPayload )

        logging.getLogger().debug("Getting id from response")
        id = createResponse.get("id")
        if not id:
            logging.getLogger().debug("ID not present in response!")
            raise Exception("Failed to get ID for newly created app!" )

        logging.getLogger().debug("Activating newly created app with id {}".format(id))
        self.SetAppActiveStatus( id, True)

        # The caller needs the client ID + secret
        logging.getLogger().debug("Returning client ID + client secret")
        return (createResponse.get("name"), createResponse.get("clientSecret"))

    def SetAppActiveStatus(self, id, status):
        appActivatePayload = {"active": status, "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:AppStatusChanger"]}
        activateResponse = self._sendRequest( "PUT", "/admin/v1/AppStatusChanger/" + id, appActivatePayload )

    def DeleteApp(self, id):
        logging.getLogger().debug("Deleting app with ID {}".format(id))
        # in order to delete an app you need to be sure it's deactivated
        self.SetAppActiveStatus(id,False)
        self._sendRequest( "DELETE", "/admin/v1/Apps/" + id, None)
        return

    def DeleteAppWithClientID(self, clientID):
        # OCI IAM will not allow more than one app to have the same "name"
        # so this will return either 0 or 1 results.
        response = self._sendRequest("GET",
                                     "/admin/v1/Apps?filter=name+eq+%22" + clientID + "%22",
                                     None)

        if response and 1 == response.get("totalResults"):
            #response.get("name") and response.get("id"):
            #return self.DeleteApp(response.get("id"))
            id = response.get("Resources")[0].get("id")
            logging.getLogger().debug( "Found app to delete - OCI IAM is {}".format(id))
            self.DeleteApp(id)
        else:
            logging.getLogger().error("Could not find app to delete!")
            raise Exception("Unable to find app to delete")

        return

    def getGroupId(self, displayName):
        response = self._sendRequest("GET",
                                     "/admin/v1/Groups?filter=displayName+eq+%22" + urllib.parse.quote(displayName) + "%22",
                                     None)
        if response and 1 == response.get("totalResults"):
            id = response.get("Resources")[0].get("id")
            logging.getLogger().debug( "Returning ID {}".format(id))
            return id
        else:
            raise Exception("Failed to get ID for group!" )

    def getAppRoleID(self, appRole):
        response = self._sendRequest("GET",
                                     "/admin/v1/AppRoles?filter=displayName+eq+%22" + urllib.parse.quote(appRole) + "%22",
                                     None)
        if response and 1 == response.get("totalResults"):
            id = response.get("Resources")[0].get("id")
            logging.getLogger().debug( "Returning ID {}".format(id))
            return id
        else:
            raise Exception("Failed to get ID for AppRole!" )

    def grantAppRoleToGroup(self, appRoleName, groupName):

        grant_payload = {
            "grantee": {
                "type": "Group",
                "value": "" + self.getGroupId(groupName) + ""
            },
            "app": {
                "value": "IDCSAppId"
            },
            "entitlement": {
                "attributeName": "appRoles",
                "attributeValue": "" + self.getAppRoleID(appRoleName) + ""
            },
            "grantMechanism": "ADMINISTRATOR_TO_GROUP",
            "schemas": [
                "urn:ietf:params:scim:schemas:oracle:idcs:Grant"
            ]
        }

        self._sendRequest("POST", "/admin/v1/Grants", grant_payload)

    def bulkRequest(self, reqs):
        bulkReq = {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations" :
                        []
        }

        bulkReq["Operations"] += reqs
        self._sendRequest("POST", "/admin/v1/Bulk", bulkReq)



    def _sendRequest(self, verb, uri, jsonpayload):
        if verb == "POST":
            logging.getLogger().debug("Sending POST payload:")
            logging.getLogger().debug(json.dumps(jsonpayload))

        # response = self.oauthClient.post(self.ociIamUrl + uri,
        try:
            response = self.oauthClient.request(verb, self.ociIamUrl + uri,
                                          json = jsonpayload,
                                          headers = {
                                             "Content-Type":"application/scim+json",
                                             "Accept":"application/scim+json,application/json"
                                        })

            logging.getLogger().debug("Status code: {}".format(response.status_code))
        except OAuth2Error as err:
            logging.getLogger().error("Error generate OAuth2 Session: %s", err)
            raise    

        if response.ok:
            logging.getLogger().debug( "Response indicates success" )
            if response.content:
                logging.getLogger().debug(response.content)
                if response.text:
                    logging.getLogger().debug(json.dumps(response.json()))
                    return response.json()
            else:
                return None
        else:
            # anything other than "OK" from OCI IAM means error
            logging.getLogger().error("Error making HTTP request")
            if response.text:
                logging.getLogger().debug(response.text)
            else:
                logging.getLogger().debug("No content to log")

            raise Exception( "HTTP request failed" )

