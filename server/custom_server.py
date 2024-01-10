import logging
import json
import pprint
import sys

from flask import session
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.resource.policy import PolicyClient
from azure.graphrbac import GraphRbacManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from msgraph.core import GraphClient 
from azure.identity import ClientSecretCredential
from azure.mgmt.appcontainers import ContainerAppsAPIClient

from commands.kc_metadata_manager.azure_metadata import Metadata as AzureMetadata

import traceback
import os
import ipaddress
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("server")
logger.setLevel(logging.INFO)

def pp(d):
    print(pprint.pformat(d))

def get_resource_groups(params):
    # Acquire a credential object using CLI-based authentication.
    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    credential = DefaultAzureCredential()
    resource_client = ResourceManagementClient(credential, subscription_id)
    group_list = resource_client.resource_groups.list()
    resource_groups = []
    sorted_entities = sorted(group_list, key=lambda x: x.name.lower(), reverse=False)
    rc_rgs = list(filter(lambda x: x.tags is not None and x.tags.get('profile') is not None and x.tags.get('profile') == params.get('env') ,sorted_entities))
    other_rgs = list(filter((lambda x: x.tags is None) ,sorted_entities))
    additional_rgs = list(filter((lambda x: x.tags is not None and x.tags.get('profile') is None) ,sorted_entities))

    final_list = rc_rgs + other_rgs + additional_rgs
    
    # for item in list(final_list):
    #     print(item.name)

    #sorted_entities = sorted(group_list, key=lambda x: x.name.lower(), reverse=False)
    for group in list(final_list):
        output_dict = {}
        is_rc = ""
        if not group.tags:
            label = f"{group.name} ({group.location})"
        else:
            if group.tags is not None:
                if group.tags.get('profile') is not None:
                    if group.tags.get('profile').lower() == params.get('env').lower():
                        is_rc = "value"
            if is_rc == '':
                label = f"{group.name} ({group.location})"
            else:
                label = f"{group.name} ({group.location}) (Managed by Rapid Cloud)"
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = label
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = group.name
        output_dict['value']['scope'] = group.id
        resource_groups.append(output_dict)
    return resource_groups

def get_object_ids():
    # Acquire a credential object using CLI-based authentication.
    try:
        #credential = ClientSecretCredential(client_id=os.environ["AZURE_CLIENT_ID"],client_secret=os.environ["AZURE_CLIENT_SECRET"],tenant_id=os.environ["AZURE_TENANT_ID"])
        graph_client = GraphClient(credential=DefaultAzureCredential())
        groups = graph_client.get('/groups?$select=displayName,id')
        entities_groups = json.dumps(groups.json())
        ent_groups = json.loads(entities_groups)

    except Exception as e:
        traceback.print_exc()
    #For the groups 
    groups = []
    for group in list(ent_groups.get('value')):
        output_dict = {}
        #print(user.get('displayName'))
        label = f"{group.get('displayName')}"
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = label
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = group.get('id')
        groups.append(output_dict)
    
    return groups

def get_locations():
    # Acquire a credential object using CLI-based authentication.
    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    credential = DefaultAzureCredential()

    subs_client = SubscriptionClient(credential)
    entities = subs_client.subscriptions.list_locations(subscription_id)

    locations = []

    for location in list(entities):
        output_dict = {}
        label = f"{location.display_name}"
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = label
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = location.name
        locations.append(output_dict)
    return locations

def get_subnets():
    # Acquire a credential object using CLI-based authentication.
    SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID", None)
    network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
    vnets = network_client.virtual_networks.list_all()

    subnets = []

    for vnet in list(vnets):
        for subnet in vnet.subnets:
            output_dict = {}
            label = f"{vnet.name} - {subnet.name} ({subnet.address_prefix})"
            output_dict['value'] = {}
            output_dict['type'] = "Theia::Option"
            output_dict['label'] = label
            output_dict['value']['type'] = "Theia::DataOption"
            output_dict['value']['value'] = subnet.id
            subnets.append(output_dict)
    return subnets

def get_subnets_for_container_app():
    # Acquire a credential object using CLI-based authentication.
    SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID", None)
    network_client = NetworkManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)
    vnets = network_client.virtual_networks.list_all()

    subnets = []

    for vnet in list(vnets):
        for subnet in vnet.subnets:
            ip_addr = ipaddress.ip_network(subnet.address_prefix)
            if ip_addr.prefixlen > 23: continue     #subnet must be at least /23
            output_dict = {}
            label = f"{vnet.name} - {subnet.name} ({subnet.address_prefix})"
            output_dict['value'] = {}
            output_dict['type'] = "Theia::Option"
            output_dict['label'] = label
            output_dict['value']['type'] = "Theia::DataOption"
            output_dict['value']['value'] = subnet.id
            subnets.append(output_dict)
    return subnets

def get_log_workspaces():
    # Acquire a credential object using CLI-based authentication.
    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    credential = DefaultAzureCredential()

    log_client = LogAnalyticsManagementClient(credential,subscription_id)
    entities = log_client.workspaces.list()

    workspaces = []

    for workspace in list(entities):
        output_dict = {}
        label = f"{workspace.name}"
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = label
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = workspace.id
        workspaces.append(output_dict)
    return workspaces

def get_managed_identities_clientid(session):
    if "env_info" in session and "subscription" in session["env_info"]:
        subscription_id = session["env_info"]["subscription"]
    
    token = get_new_token()
    api_call_headers = {'Authorization': 'Bearer ' + token}
    response = requests.get(f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31",
                            headers=api_call_headers, verify=False)

    identities = []

    response2 = json.loads(response.text)
    for identity in response2['value']:
        output_dict = {}
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = identity['name']
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = f"{identity['id'].replace('resourcegroups', 'resourceGroups')};{identity['properties']['clientId']}"
        identities.append(output_dict)
    return identities

def get_new_token():
    tokenCredential = DefaultAzureCredential()
    scope = "https://management.core.windows.net/.default"
    access_token = tokenCredential.get_token(scope)
    return access_token.token
             
def get_rc_aks_clusters():
    print ("getting clusters")
    return get_azure_infra_items("create_aks")

def get_rc_container_app_envs():
    return get_azure_infra_items("create_app_environment")

def get_azure_infra_items(command):
    args = {}
    args["cloud"] = "azure"
    args["env"] = session["env"]
    print (f"env: {args['env']}")
    azure_metadata = AzureMetadata(args)

    extra_filters = {"profile":f"{args['env']}", "command": command}
    items = azure_metadata.get_all_resources(extra_filters=extra_filters)

    select_items = []
    for item in items:
        output_dict = {}
        label = item.get("resource_name")
        output_dict['value'] = {}
        output_dict['type'] = "Theia::Option"
        output_dict['label'] = label
        output_dict['value']['type'] = "Theia::DataOption"
        output_dict['value']['value'] = item.get("resource_name")
        select_items.append(output_dict)
    return select_items

def custom_endpoint(action, params, boto3_session, user_session):
    if action == "aks_clusters":
        return get_rc_aks_clusters()
    elif action == "container_app_envs":
        return get_rc_container_app_envs()
    elif action == "managedidentities_clientid":
        return get_managed_identities_clientid(user_session)
    else:
        pp(f"no such endpoint: {action}")
        return ["no such endpoint"]

    return []
