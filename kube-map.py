#!/usr/bin/env python3

import glob
import json
import sys
import os

with open("config.json", "rt") as config_file:
    config = json.load(config_file)

outputFolderPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'output-dir')
skipNamespaces = config['skipNamespaces']
skipKinds = config['skipKinds']
skipSpecificDeployments = config['skipSpecificDeployments']
skipDeploymentPrefix = config['skipDeploymentPrefix']
skipDeploymentSuffix = config['skipDeploymentSuffix']
includeVCTvolumes = config['includeVCTvolumes']   # Include PVCs that were created by the volumeClaimTemplate within the deployment resource
skipIngressClassName = config['skipIngressClassName']  # Useful if for some reason you are stuck with two (old & new) nginx versions & would like to only link a specific one... ¯\_(ツ)_/¯
outputUnmappedResources = config['outputUnmappedResources']  # Create a file containing eligible resources which were not mapped. a File per namespace is created for ease of readability

# Output Lists
deploymentsList = []
namespaceList = []
serviceList = []
serviceMonitorList = []
serviceAccountList = []
roleBindingList = []
clusterRoleBindingList = []
roleList = []
clusterRoleList = []
persistentVolumeClaimList = []
podDisruptionBudgetList = []
cronJobList = []
jobList = []
configMapList = []
secretList = []
externalSecretList = []
ingressList = []
ambassadorMappingList = []
ambassadorHostList = []
ambassadorFilterPolicyList = []
ambassadorFilterList = []


def dictSanitiser(object):  # Remove duplicate objects from list
    sanitised = []
    for obj in object:
        if obj not in sanitised:
            sanitised.append(obj)
    return sanitised


def externalSecrets(secretObject, externalSecretList, resourceMap):
    if secretObject['metadata'].get('ownerReferences', []):
        for ownerRef in secretObject['metadata']['ownerReferences']:
            if ownerRef.get('kind', '') == "ExternalSecret" and ownerRef.get('name', ''):   # This means that the secret is ESO managed
                for externalSecret in externalSecretList:
                    if ownerRef['name'] == externalSecret['metadata']['name'] and secretObject['metadata']['namespace'] == externalSecret['metadata']['namespace']:
                        resourceMap.append(externalSecret)
    return


def serviceAccounts(serviceAccountName, serviceAccountNamespace, serviceAccountList, secretList, roleBindingList, clusterRoleBindingList, roleList, clusterRoleList, resourceMap):
    for serviceAccount in serviceAccountList:
        if serviceAccountName == serviceAccount['metadata']['name'] and serviceAccountNamespace == serviceAccount['metadata']['namespace']:
            resourceMap.append(serviceAccount)
            for secret in secretList:
                if serviceAccount.get("imagePullSecrets", []):
                    if serviceAccount['imagePullSecrets'][0].get('name', "") == secret['metadata']['name'] and serviceAccount['metadata']['namespace'] == secret['metadata']['namespace']:
                        resourceMap.append(secret)
                for serviceSecret in serviceAccount.get("secrets", []):
                    if serviceSecret['name'] == secret['metadata']['name'] and serviceAccount['metadata']['namespace'] == secret['metadata']['namespace']:
                        resourceMap.append(secret)
            roleRefName = ""
            roleRefKind = ""
            for roleBinding in roleBindingList:
                for subject in roleBinding['subjects']:
                    if subject['kind'] == "ServiceAccount" and subject['name'] == serviceAccountName and roleBinding['metadata']['namespace'] == serviceAccountNamespace:
                        if "'" not in roleBinding['metadata']['name']:  # Just in case there are wrongly named Role Bindings containing '.
                            resourceMap.append(roleBinding)
                            roleRefName = roleBinding['roleRef']['name']
                            roleRefKind = roleBinding['roleRef']['kind']
            for clusterRoleBinding in clusterRoleBindingList:
                for subject in clusterRoleBinding.get('subjects', []):
                    if subject['kind'] == "ServiceAccount" and subject['name'] == serviceAccountName:   # Just in case there are wrongly named Cluster Role Bindings containing '.
                        if "'" not in clusterRoleBinding['metadata']['name']:
                            resourceMap.append(clusterRoleBinding)
                            roleRefName = clusterRoleBinding['roleRef']['name']
                            roleRefKind = clusterRoleBinding['roleRef']['kind']
            if roleRefName and roleRefKind:
                if roleRefKind == "ClusterRole":
                    roleList = clusterRoleList
                elif roleRefKind == "Role":
                    roleList = roleList
                for role in roleList:
                    if roleRefName == role['metadata']['name']:
                        resourceMap.append(role)
            break


def serviceMonitor(resource, serviceMonitorList, resourceMap):
    for serviceMonitor in serviceMonitorList:
        namespaceMatched = False
        if serviceMonitor['spec'].get("namespaceSelector", {}):  # ServiceMonitor has namespaceSelector defined
            for namespaceSelector in serviceMonitor['spec'].get("namespaceSelector", {}).get('matchNames', []):
                if resource['metadata']['namespace'] == namespaceSelector:  # Checking if resource namespace is in serviceMonitor namespaceSelector
                    namespaceMatched = True
            if namespaceMatched:
                if serviceMonitor['spec'].get('selector', {}):
                    if serviceMonitor['spec']['selector'].get('matchLabels', {}).items() <= resource['metadata'].get('labels', {}).items(): # Checking if matchLabel matches deployment labels
                        resourceMap.append(serviceMonitor)
                    elif serviceMonitor['spec']['selector'].get('matchLabels', {}).items() <= resource['spec'].get('template', {}).get('metadata', {}).get('labels', {}).items(): # Checking if matchLabel matches pod labels
                        resourceMap.append(serviceMonitor)
                else:   # If no selector defined, match only by namespace which already matched
                    resourceMap.append(serviceMonitor)
        else:   # This means the service has only selector defined
            if serviceMonitor['spec']['selector'].get('matchLabels', {}).items() <= resource['metadata'].get('labels', {}).items(): # Checking if matchLabel matches deployment labels
                resourceMap.append(serviceMonitor)
            elif serviceMonitor['spec']['selector'].get('matchLabels', {}).items() <= resource['spec'].get('template', {}).get('metadata', {}).get('labels', {}).items(): # Checking if matchLabel matches pod labels
                resourceMap.append(serviceMonitor)


def ingress(resource, ingressList, resourceMap):
    for ingress in ingressList:
        ingressMatched = False
        for ingressRule in ingress['spec'].get('rules', []):    # Looping over ingress rules
            if not ingressMatched:
                for rulePath in ingressRule.get('http', {}).get('paths', {}):
                    if rulePath.get('backend', {}).get('service', {}).get('name', "") == resource['metadata']['name'] and ingress['metadata']['namespace'] == resource['metadata']['namespace']:    # Checking if the ingress resides in the same NS & has this service as backend
                        resourceMap.append(ingress)
                        ingressMatched = True
                        break # no need to process additional rule paths


def ambassadorMapping(resource, ambassadorMappingList, namespaceList, ambassadorHostList, resourceMap):
    global externalMappings
    for mapping in ambassadorMappingList:
        if not mapping['spec'].get('service', "").startswith("http") and not mapping['spec'].get('service', "").endswith(".com") and not mapping['spec'].get('service', "").endswith(".co.uk") and not mapping['spec'].get('service', "").endswith(".es") and not mapping['spec'].get('service', "").endswith(".ca"):
            mappingService = mapping['spec'].get('service', "").split(":")[0]
            if "." not in mappingService:   # This means that the mapping must reside in the same namespace as service
                mappingServiceNamespace = mapping['metadata']['namespace']
            else:
                validNamespace = False
                for namespace in namespaceList:     # Checking if the value is a valid namespace since service might reference an external site example: www.example.com
                    if mappingService.split(".")[1] ==  namespace['metadata']['name']:
                        mappingServiceNamespace = mappingService.split(".")[1]
                        validNamespace = True
                        break
                if not validNamespace:  # If no valid namespace in service, default to mapping namespace
                    mappingServiceNamespace = mapping['metadata']['namespace']
            if mappingService == resource['metadata']['name'] and mappingServiceNamespace == resource['metadata']['namespace']:     # Confirm mapping name and namespace match resource name and namespace
                resourceMap.append(mapping)
                ambassadorHosts(mapping, ambassadorHostList, resourceMap)
        else:
            if mapping not in externalMappings:
                externalMappings.append(mapping)
                ambassadorHosts(mapping, ambassadorHostList, externalMappings)


def ambassadorHosts(resource, ambassadorHostList, resourceMap):
    matchedhostnameLen = 0
    matchBoth = False
    for host in ambassadorHostList:
        hostMatched = False
        labelsMatched = False
        if (host['spec'].get('mappingSelector') or host['spec'].get('selector')) and resource['spec'].get("host", ""): # Host has both host & label matching
            matchBoth = True    # Both host in mapping & mappingSelector in host are defined, we must match both
        if host['spec'].get("hostname", "") == resource['spec'].get("host", ""):    # Check if host exactly matches mapping host
            matchedhostnameLen = len(resource['spec'].get("host", ""))
            hostMatched = True
        elif host['spec'].get("hostname", "").replace('*.', '').replace('.*', '') in resource['spec'].get("host", ""):  # Check if wildcard host matches mapping host
            if len(host['spec'].get("hostname", "").replace('*.', '').replace('.*', '')) > matchedhostnameLen:  # Is this matching wildcard specific to this mapping? If so use it
                matchedhostnameLen = len(host['spec'].get("hostname", "").replace('*.', '').replace('.*', ''))
                hostMatched = True
        elif host['spec'].get("hostname", "") == "*":   # The default catch all host
            if len(host['spec'].get("hostname", "")) > matchedhostnameLen:  # Is this matching wildcard the default? If so use it
                matchedhostnameLen = len(host['spec'].get("hostname", ""))
                hostMatched = True
        matchlbl = "mappingSelector"    # Default for v3alpha1
        if host['spec'].get('selector', {}).get('matchLabels', {}):
            matchlbl = "selector"   # Used in v2 apiversion
        if host['spec'].get(matchlbl, {}).get('matchLabels', {}).items() <= resource['metadata'].get('labels', {}).items() and host['spec'].get(matchlbl, {}).get('matchLabels', {}) != {}: # Checking if selector/mappingSelector matches mapping labels
            labelsMatched = True
        if hostMatched and labelsMatched and hostMatched:
            resourceMap.append(host)
        elif not matchBoth and hostMatched:
            resourceMap.append(host)
        elif not matchBoth and labelsMatched:
            resourceMap.append(host)


with open(sys.argv[1], 'r') as file:
    try:
        fileContent = json.load(file)
    except:
        print("Seems like your JSON input file is not valid. Kindly source a valid JSON file!")
        exit()


allResources = []   # List containing all eligible resources
for resources in fileContent['items']:
    resourceEligible = False
    if resources['kind'] not in skipKinds:
        if resources['metadata'].get('namespace', "") not in skipNamespaces or resources['kind'] == "Host":
            if resources['metadata']['name'] not in skipSpecificDeployments:
                resourceEligible = True
                for prefix in skipDeploymentPrefix:
                    if str(resources['metadata']['name']).startswith(prefix):
                        resourceEligible = False
                        break
                for suffix in skipDeploymentSuffix:
                    if str(resources['metadata']['name']).endswith(suffix):
                        resourceEligible = False
                        break
            if resourceEligible:
                if resources['kind'] == "Deployment" or resources['kind'] == "StatefulSet" or resources['kind'] == "DaemonSet":
                    deploymentsList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Namespace":
                    namespaceList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Service":
                    serviceList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "ServiceMonitor":
                    serviceMonitorList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "ServiceAccount":
                    serviceAccountList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "RoleBinding":
                    roleBindingList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "ClusterRoleBinding":
                    clusterRoleBindingList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Role":
                    roleList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "ClusterRole":
                    clusterRoleList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "PersistentVolumeClaim":
                    persistentVolumeClaimList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "PodDisruptionBudget":
                    podDisruptionBudgetList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "CronJob":
                    cronJobList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Job":
                    jobList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "ConfigMap":
                    configMapList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Secret":
                    secretList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "ExternalSecret":
                    externalSecretList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Ingress":
                    if resources['spec'].get('ingressClassName', "") not in skipIngressClassName or resources['metadata'].get('annotations', {}).get("kubernetes.io/ingress.class", "") not in skipIngressClassName:
                        ingressList.append(resources)
                        allResources.append(resources)
                elif resources['kind'] == "Mapping":
                    ambassadorMappingList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Host":
                    ambassadorHostList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "FilterPolicy":
                    ambassadorFilterPolicyList.append(resources)
                    allResources.append(resources)
                elif resources['kind'] == "Filter":
                    ambassadorFilterList.append(resources)
                    allResources.append(resources)


sanitisedJobNamesList = []   # Temp list to remove duplicate jobs
sanitisedJobList = []   # List holding Jobs which were not created by a CronJob
for job in reversed(jobList):   # To get the latest job only
    jobFromCronJob = False
    for cronjob in cronJobList:
        if not cronjob.get('spec', {}).get('jobTemplate', {}).get('metadata', {}).get('name', ""):
            if job['metadata']['name'].startswith(cronjob['metadata']['name']):
                jobFromCronJob = True
                break
        elif job['metadata']['name'].startswith(cronjob.get('spec', {}).get('jobTemplate', {}).get('metadata', {}).get('name', "")):
            jobFromCronJob = True
            break
    if not jobFromCronJob:
        if job['metadata']['name'].replace('-'+job['metadata']['name'].split('-')[-1], '') not in sanitisedJobNamesList:
            sanitisedJobNamesList.append(job['metadata']['name'].replace('-'+job['metadata']['name'].split('-')[-1], ''))
            sanitisedJobList.append(job)


# Clean output folder
if os.path.exists(outputFolderPath):
    print("Cleaning output folder " + os.path.join(outputFolderPath, "*.json"))
    for f in glob.glob(os.path.join(outputFolderPath, "*.json")):
        os.remove(f)
else:
    os.makedirs(outputFolderPath)

mappedResources = []    # List of resources which were mapped.
externalMappings = []   # List of external ambassador mappings
unmappedFilters = []   # List of non 'External' ambassador Filters
for resource in deploymentsList:
    resourceMap = []
    resourceMap.append(resource)    # Adding the deployment itself
    for namespace in namespaceList:
        if resource['metadata']['namespace'] == namespace['metadata']['name']:  # Adding namespace resource where this deployment is deployed
            resourceMap.append(namespace)
    if resource['spec']['template']['spec'].get('volumes', []):     # Getting configmaps & secrets mounted as Volumes
        for volume in range(len(resource['spec']['template']['spec'].get('volumes', []))):
            if resource['spec']['template']['spec']['volumes'][volume].get('configMap', {}):
                for configMap in configMapList:
                    if configMap['metadata']['name'] == resource['spec']['template']['spec']['volumes'][volume]['configMap']['name'] and configMap['metadata']['namespace'] == resource['metadata']['namespace']:
                        resourceMap.append(configMap)
            elif resource['spec']['template']['spec']['volumes'][volume].get('secret', {}):
                for secret in secretList:
                    if secret['metadata']['name'] == resource['spec']['template']['spec']['volumes'][volume]['secret']['secretName'] and secret['metadata']['namespace'] == resource['metadata']['namespace']:
                        resourceMap.append(secret)
                        externalSecrets(secret, externalSecretList, resourceMap)     # Checking if secret is ESO managed & adding ESO JSON object if it is.
    for container in range(len(resource['spec']['template']['spec'].get('containers', []))):
        for envFrom in resource['spec']['template']['spec']['containers'][container].get("envFrom", []):    # Getting configmaps & secrets sourced as ENVs
            if envFrom.get('configMapRef', {}):
                for configMap in configMapList:
                    if configMap['metadata']['name'] == envFrom['configMapRef']['name'] and configMap['metadata']['namespace'] == resource['metadata']['namespace']:
                        resourceMap.append(configMap)
            elif envFrom.get('secretRef', {}):
                for secret in secretList:
                    if secret['metadata']['name'] == envFrom['secretRef']['name'] and secret['metadata']['namespace'] == resource['metadata']['namespace']:
                        resourceMap.append(secret)
                        externalSecrets(secret, externalSecretList, resourceMap)     # Checking if secret is ESO managed & adding ESO JSON object if it is.
        for valueFrom in resource['spec']['template']['spec']['containers'][container].get("env",[]):       # Getting configmaps & secrets sourced as specific ENV vars
            if valueFrom.get('valueFrom', {}).get('configMapKeyRef', {}):
                for configMap in configMapList:
                    if configMap['metadata']['name'] == valueFrom['valueFrom']['configMapKeyRef']['name'] and configMap['metadata']['namespace'] == resource['metadata']['namespace']:
                        resourceMap.append(configMap)
            elif valueFrom.get('valueFrom', {}).get('secretKeyRef', {}):
                for secret in secretList:
                    if secret['metadata']['name'] == valueFrom['valueFrom']['secretKeyRef']['name'] and secret['metadata']['namespace'] == resource['metadata']['namespace']:
                        resourceMap.append(secret)
                        externalSecrets(secret, externalSecretList, resourceMap)     # Checking if secret is ESO managed & adding ESO JSON object if it is.
    if resource['spec']['template']['spec'].get('serviceAccountName', "default") != 'default':
        serviceAccounts(resource['spec']['template']['spec']['serviceAccountName'], resource['metadata']['namespace'], serviceAccountList, secretList, roleBindingList, clusterRoleBindingList, roleList, clusterRoleList, resourceMap)     # Getting custom service accounts & its secrets, RoleBinding & role
    elif resource['spec']['template']['spec'].get('serviceAccount', "default") != 'default':
        serviceAccounts(resource['spec']['template']['spec']['serviceAccount'], resource['metadata']['namespace'], serviceAccountList, secretList, roleBindingList, clusterRoleBindingList, roleList, clusterRoleList, resourceMap)     # Getting custom service accounts & its secrets, RoleBinding & role
    if resource['spec']['template']['spec'].get('imagePullSecrets', []):
        for imagePullSecret in resource['spec']['template']['spec']['imagePullSecrets']:
            for secret in secretList:
                if imagePullSecret['name'] == secret['metadata']['name'] and resource['metadata']['namespace'] == secret['metadata']['namespace']:
                    resourceMap.append(secret)
    for volume in resource['spec']['template']['spec'].get('volumes', []):  # Catering for PVC Claims
        if volume.get('persistentVolumeClaim', {}):
            for pvc in persistentVolumeClaimList:
                if pvc['metadata']['name'] == volume['persistentVolumeClaim']['claimName'] and pvc['metadata']['namespace'] == resource['metadata']['namespace']:
                    resourceMap.append(pvc)
    if includeVCTvolumes:
        for volumeClaim in resource['spec'].get('volumeClaimTemplates', []):
            for pvc in persistentVolumeClaimList:
                if pvc['metadata']['name'].startswith(volumeClaim['metadata']['name']+"-"+resource['metadata']['name']) and resource['metadata']['namespace'] == pvc['metadata']['namespace']:
                    resourceMap.append(pvc)
    serviceMonitor(resource, serviceMonitorList, resourceMap)   # Build service monitor relation
    depolymentServices = []
    for service in serviceList:
        if service['spec'].get('selector', {}): # We are not catering for services of type External Name since without proper labeling this is tricky
            if service['metadata']['namespace'] == resource['metadata']['namespace']:
                if service['spec'].get('selector', {}).items() <= resource['metadata'].get('labels', {}).items(): # Checking if selector matches deployment labels
                    resourceMap.append(service)
                    depolymentServices.append(service['metadata']['name'])
                    serviceMonitor(service, serviceMonitorList, resourceMap)   # Build service monitor relation
                    ingress(service, ingressList, resourceMap)      # Build Ingress relation
                    ambassadorMapping(service, ambassadorMappingList, namespaceList, ambassadorHostList, resourceMap)      # Build Ambassador Mappings relation
                elif service['spec'].get('selector', {}).items() <= resource['spec']['template']['metadata'].get('labels', {}).items(): # Checking if selector matches pod labels
                    resourceMap.append(service)
                    depolymentServices.append(service['metadata']['name'])
                    serviceMonitor(service, serviceMonitorList, resourceMap)   # Build service monitor relation
                    ingress(service, ingressList, resourceMap)      # Build Ingress relation
                    ambassadorMapping(service, ambassadorMappingList, namespaceList, ambassadorHostList, resourceMap)      # Build Ambassador Mappings relation
    for podDisruptionBudget in podDisruptionBudgetList:
        if podDisruptionBudget.get('spec', {}).get('selector', {}).get('matchLabels', {}).items() <= resource['metadata'].get('labels', {}).items():    # If podDisruptionBudget selector labels in  resource labels
            resourceMap.append(podDisruptionBudget)     # Append podDisruptionBudget relation
    for ambassadorFilter in ambassadorFilterList:
        if ambassadorFilter.get('spec', {}).get('External', {}):    # If Filter is not of kind 'External', we will add it to ambassador Filters output file
            if ambassadorFilter['spec']['External'].get("auth_service", "").split(".")[-1].split(":")[0] == resource['metadata']['namespace'] and (ambassadorFilter['spec']['External'].get("auth_service", "").replace('.'+ambassadorFilter['spec']['External'].get("auth_service", "").split(".")[-1], '') == resource['metadata']['name'] or ambassadorFilter['spec']['External'].get("auth_service", "").replace('.'+ambassadorFilter['spec']['External'].get("auth_service", "").split(".")[-1], '') in depolymentServices):
                resourceMap.append(ambassadorFilter)     # Append ambassadorFilter relation
                for ambassadorFilterPolicy in ambassadorFilterPolicyList:   # Checking for ambassadorFilterPolicy relation
                    for ambassadorFilterPolicyObject in ambassadorFilterPolicy['spec'].get('rules', []):
                        for afilter in ambassadorFilterPolicyObject.get('filters', []):
                            if afilter['name'] == ambassadorFilter['metadata']['name'] and afilter.get('namespace', ambassadorFilterPolicy['metadata']['namespace']) == ambassadorFilter['metadata']['namespace']:
                                resourceMap.append(ambassadorFilterPolicy)  # Append ambassadorFilterPolicy relation
            elif ambassadorFilter['spec']['External'].get("auth_service", "").split(".")[-1].split(":")[0] == 'ambassador' or ambassadorFilter['spec']['External'].get("auth_service", "").replace('.'+ambassadorFilter['spec']['External'].get("auth_service", "").split(".")[-1], '') == 'edge-stack':
                if ambassadorFilter not in unmappedFilters:
                    unmappedFilters.append(ambassadorFilter)    # If using the ambassador auth service, add the filter resource to unmapped Filters json
                    for ambassadorFilterPolicy in ambassadorFilterPolicyList:   # Checking for ambassadorFilterPolicy relation
                        for ambassadorFilterPolicyObject in ambassadorFilterPolicy['spec'].get('rules', []):
                            for afilter in ambassadorFilterPolicyObject.get('filters', []):
                                if afilter['name'] == ambassadorFilter['metadata']['name'] and afilter.get('namespace', ambassadorFilterPolicy['metadata']['namespace']) == ambassadorFilter['metadata']['namespace']:
                                    unmappedFilters.append(ambassadorFilterPolicy)  # Append ambassadorFilterPolicy relation
        else:
            if ambassadorFilter not in unmappedFilters:
                unmappedFilters.append(ambassadorFilter)
                for ambassadorFilterPolicy in ambassadorFilterPolicyList:   # Checking for ambassadorFilterPolicy relation
                    for ambassadorFilterPolicyObject in ambassadorFilterPolicy['spec'].get('rules', []):
                        for afilter in ambassadorFilterPolicyObject.get('filters', []):
                            if afilter['name'] == ambassadorFilter['metadata']['name'] and afilter.get('namespace', ambassadorFilterPolicy['metadata']['namespace']) == ambassadorFilter['metadata']['namespace']:
                                unmappedFilters.append(ambassadorFilterPolicy)  # Append ambassadorFilterPolicy relation
    for cronjob in cronJobList:     # We try to map cronjob to deployment based on deployment/cronjob name, by volumes used, by env vars passed
        cronjobMapped = False   # We need this to determine if we successfully mapped the cronjob or not
        cronjobName = cronjob['metadata']['name'].replace('-migration', '').replace('-scheduler-job', '').replace('-cronjob', '').replace('-cron-job', '').replace('-scheduler', '') # Try and remove any cronjob related suffix to match with resource name
        if resource['metadata']['name'] == cronjobName or resource['metadata']['name'] == cronjob['metadata']['name']: # Matched a cronjob to this deployment. Will map it to this resource.
            resourceMap.append(cronjob)
            cronjobMapped = True
        elif cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('volumes', []):     # Getting configmaps & secrets mounted as Volumes to map cronjob with resource if they use the same secrets/configmaps.
            for volume in range(len(cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('volumes', []))):
                if cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume].get('configMap', {}):
                    for configMap in resourceMap:
                        if configMap['kind'] == 'ConfigMap' and configMap['metadata']['name'] == cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume]['configMap']['name'] and configMap['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(cronjob)
                            cronjobMapped = True
                elif cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume].get('secret', {}):
                    for secret in resourceMap:
                        if secret['kind'] == 'Secret' and secret['metadata']['name'] == cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume]['secret']['secretName'] and secret['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(cronjob)
                            cronjobMapped = True
        if not cronjobMapped:   # If still not mapped to resource, check envFrom and env vars for possible mounted secrets/configmaps
            for container in range(len(cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('containers', []))):
                for envFrom in cronjob['spec']['jobTemplate']['spec']['template']['spec']['containers'][container].get("envFrom", []):    # Getting configmaps & secrets sourced as ENVs
                    if envFrom.get('configMapRef', {}):
                        for configMap in resourceMap:
                            if configMap['kind'] == 'ConfigMap' and configMap['metadata']['name'] == envFrom['configMapRef']['name'] and configMap['metadata']['namespace'] == cronjob['metadata']['namespace']:
                                resourceMap.append(cronjob)
                    elif envFrom.get('secretRef', {}):
                        for secret in resourceMap:
                            if secret['kind'] == 'Secret' and secret['metadata']['name'] == envFrom['secretRef']['name'] and secret['metadata']['namespace'] == cronjob['metadata']['namespace']:
                                resourceMap.append(cronjob)
            for valueFrom in cronjob['spec']['jobTemplate']['spec']['template']['spec']['containers'][container].get("env",[]):       # Getting configmaps & secrets sourced as specific ENV vars
                if valueFrom.get('valueFrom', {}).get('configMapKeyRef', {}):
                    for configMap in resourceMap:
                        if configMap['kind'] == 'ConfigMap' and configMap['metadata']['name'] == valueFrom['valueFrom']['configMapKeyRef']['name'] and configMap['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(cronjob)
                elif valueFrom.get('valueFrom', {}).get('secretKeyRef', {}):
                    for secret in resourceMap:
                        if secret['kind'] == 'Secret' and secret['metadata']['name'] == valueFrom['valueFrom']['secretKeyRef']['name'] and secret['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(cronjob)
    for job in sanitisedJobList:     # We try to map job to deployment based on deployment/job name, by volumes used, by env vars passed
        jobMapped = False   # We need this to determine if we successfully mapped the job or not
        jobName = job['metadata']['name'].replace('-'+job['metadata']['name'].split('-')[-1], '').replace('-migration', '').replace('-scheduler-job', '').replace('-job', '').replace('-scheduler', '').replace('-restore', '').replace('-monthly', '').replace('-weekly', '') # Try and remove any cronjob related suffix to match with resource name
        if (resource['metadata']['name'] == jobName or resource['metadata']['name'] == job['metadata']['name']) and (resource['metadata']['namespace'] == job['metadata']['name']): # Matched a job to this deployment. Will map it to this resource.
            resourceMap.append(job)
            jobMapped = True
        elif job['spec']['template']['spec'].get('volumes', []):     # Getting configmaps & secrets mounted as Volumes to map job with resource if they use the same secrets/configmaps.
            for volume in range(len(job['spec']['template']['spec'].get('volumes', []))):
                if job['spec']['template']['spec']['volumes'][volume].get('configMap', {}):
                    for configMap in resourceMap:
                        if configMap['kind'] == 'ConfigMap' and configMap['metadata']['name'] == job['spec']['template']['spec']['volumes'][volume]['configMap']['name'] and configMap['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(job)
                            jobMapped = True
                elif job['spec']['template']['spec']['volumes'][volume].get('secret', {}):
                    for secret in resourceMap:
                        if secret['kind'] == 'Secret' and secret['metadata']['name'] == job['spec']['template']['spec']['volumes'][volume]['secret']['secretName'] and secret['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(job)
                            jobMapped = True
        if not jobMapped:   # If still not mapped to resource, check envFrom and env vars for possible mounted secrets/configmaps
            for container in range(len(job['spec']['template']['spec'].get('containers', []))):
                for envFrom in job['spec']['template']['spec']['containers'][container].get("envFrom", []):    # Getting configmaps & secrets sourced as ENVs
                    if envFrom.get('configMapRef', {}):
                        for configMap in resourceMap:
                            if configMap['kind'] == 'ConfigMap' and configMap['metadata']['name'] == envFrom['configMapRef']['name'] and configMap['metadata']['namespace'] == job['metadata']['namespace']:
                                resourceMap.append(job)
                    elif envFrom.get('secretRef', {}):
                        for secret in resourceMap:
                            if secret['kind'] == 'Secret' and secret['metadata']['name'] == envFrom['secretRef']['name'] and secret['metadata']['namespace'] == job['metadata']['namespace']:
                                resourceMap.append(job)
            for valueFrom in job['spec']['template']['spec']['containers'][container].get("env",[]):       # Getting configmaps & secrets sourced as specific ENV vars
                if valueFrom.get('valueFrom', {}).get('configMapKeyRef', {}):
                    for configMap in resourceMap:
                        if configMap['kind'] == 'ConfigMap' and configMap['metadata']['name'] == valueFrom['valueFrom']['configMapKeyRef']['name'] and configMap['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(job)
                elif valueFrom.get('valueFrom', {}).get('secretKeyRef', {}):
                    for secret in resourceMap:
                        if secret['kind'] == 'Secret' and secret['metadata']['name'] == valueFrom['valueFrom']['secretKeyRef']['name'] and secret['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(job)

    for resourceAdded in resourceMap:   # Adds all mapped resources to the list for later processing
        mappedResources.append(resourceAdded)

    with open(os.path.join(outputFolderPath, str(resource['metadata']['namespace'])+'_'+str(resource['metadata']['name'])+'.json'), "w") as outputFile:
        json.dump(dictSanitiser(resourceMap), outputFile, indent=4, sort_keys=True)     # Output resource file with all its mapped resources


for cronjob in cronJobList:     # Mapping standalone cronJobs with their resources
    if cronjob not in mappedResources:
        resourceMap = []
        resourceMap.append(cronjob)    # Adding the cronjob itself
        if cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('serviceAccountName', "default") != 'default':    # Getting serviceAccount used by cronjob
            serviceAccounts(cronjob['spec']['jobTemplate']['spec']['template']['spec']['serviceAccountName'], cronjob['metadata']['namespace'], serviceAccountList, secretList, roleBindingList, clusterRoleBindingList, roleList, clusterRoleList, resourceMap)     # Getting custom service accounts & its secrets, RoleBinding & role
        elif cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('serviceAccount', "default") != 'default':  # Getting serviceAccount used by cronjob
            serviceAccounts(cronjob['spec']['jobTemplate']['spec']['template']['spec']['serviceAccount'], cronjob['metadata']['namespace'], serviceAccountList, secretList, roleBindingList, clusterRoleBindingList, roleList, clusterRoleList, resourceMap)     # Getting custom service accounts & its secrets, RoleBinding & role
        if cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('volumes', []):     # Getting configmaps & secrets mounted as Volumes
            for volume in range(len(cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('volumes', []))):
                if cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume].get('configMap', {}):
                    for configMap in configMapList:
                        if configMap['metadata']['name'] == cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume]['configMap']['name'] and configMap['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(configMap)
                elif cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume].get('secret', {}):
                    for secret in secretList:
                        if secret['metadata']['name'] == cronjob['spec']['jobTemplate']['spec']['template']['spec']['volumes'][volume]['secret']['secretName'] and secret['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(secret)
        for container in range(len(cronjob['spec']['jobTemplate']['spec']['template']['spec'].get('containers', []))):
            for envFrom in cronjob['spec']['jobTemplate']['spec']['template']['spec']['containers'][container].get("envFrom", []):    # Getting configmaps & secrets sourced as ENVs
                if envFrom.get('configMapRef', {}):
                    for configMap in configMapList:
                        if configMap['metadata']['name'] == envFrom['configMapRef']['name'] and configMap['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(configMap)
                elif envFrom.get('secretRef', {}):
                    for secret in secretList:
                        if secret['metadata']['name'] == envFrom['secretRef']['name'] and secret['metadata']['namespace'] == cronjob['metadata']['namespace']:
                            resourceMap.append(secret)
        for valueFrom in cronjob['spec']['jobTemplate']['spec']['template']['spec']['containers'][container].get("env",[]):       # Getting configmaps & secrets sourced as specific ENV vars
            if valueFrom.get('valueFrom', {}).get('configMapKeyRef', {}):
                for configMap in configMapList:
                    if configMap['metadata']['name'] == valueFrom['valueFrom']['configMapKeyRef']['name'] and configMap['metadata']['namespace'] == cronjob['metadata']['namespace']:
                        resourceMap.append(configMap)
            elif valueFrom.get('valueFrom', {}).get('secretKeyRef', {}):
                for secret in secretList:
                    if secret['metadata']['name'] == valueFrom['valueFrom']['secretKeyRef']['name'] and secret['metadata']['namespace'] == cronjob['metadata']['namespace']:
                        resourceMap.append(secret)

        for resourceAdded in resourceMap:   # Adds all mapped resources to the list for later processing
            mappedResources.append(resourceAdded)

        with open(os.path.join(outputFolderPath, str(cronjob['metadata']['namespace'])+'_'+str(cronjob['metadata']['name'])+'-cronjob.json'), "w") as outputFile:
            json.dump(dictSanitiser(resourceMap), outputFile, indent=4, sort_keys=True) # Output cronjob file with all its mapped resources


for job in sanitisedJobList:     # Mapping standalone jobs with their resources
    if job not in mappedResources:
        resourceMap = []
        resourceMap.append(job)    # Adding the job itself
        if job['spec']['template']['spec'].get('serviceAccountName', "default") != 'default':    # Getting serviceAccount used by job
            serviceAccounts(job['spec']['template']['spec']['serviceAccountName'], job['metadata']['namespace'], serviceAccountList, secretList, roleBindingList, clusterRoleBindingList, roleList, clusterRoleList, resourceMap)     # Getting custom service accounts & its secrets, RoleBinding & role
        elif job['spec']['template']['spec'].get('serviceAccount', "default") != 'default':  # Getting serviceAccount used by job
            serviceAccounts(job['spec']['template']['spec']['serviceAccount'], job['metadata']['namespace'], serviceAccountList, secretList, roleBindingList, clusterRoleBindingList, roleList, clusterRoleList, resourceMap)     # Getting custom service accounts & its secrets, RoleBinding & role
        if job['spec']['template']['spec'].get('volumes', []):     # Getting configmaps & secrets mounted as Volumes
            for volume in range(len(job['spec']['template']['spec'].get('volumes', []))):
                if job['spec']['template']['spec']['volumes'][volume].get('configMap', {}):
                    for configMap in configMapList:
                        if configMap['metadata']['name'] == job['spec']['template']['spec']['volumes'][volume]['configMap']['name'] and configMap['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(configMap)
                elif job['spec']['template']['spec']['volumes'][volume].get('secret', {}):
                    for secret in secretList:
                        if secret['metadata']['name'] == job['spec']['template']['spec']['volumes'][volume]['secret']['secretName'] and secret['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(secret)
        for container in range(len(job['spec']['template']['spec'].get('containers', []))):
            for envFrom in job['spec']['template']['spec']['containers'][container].get("envFrom", []):    # Getting configmaps & secrets sourced as ENVs
                if envFrom.get('configMapRef', {}):
                    for configMap in configMapList:
                        if configMap['metadata']['name'] == envFrom['configMapRef']['name'] and configMap['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(configMap)
                elif envFrom.get('secretRef', {}):
                    for secret in secretList:
                        if secret['metadata']['name'] == envFrom['secretRef']['name'] and secret['metadata']['namespace'] == job['metadata']['namespace']:
                            resourceMap.append(secret)
        for valueFrom in job['spec']['template']['spec']['containers'][container].get("env",[]):       # Getting configmaps & secrets sourced as specific ENV vars
            if valueFrom.get('valueFrom', {}).get('configMapKeyRef', {}):
                for configMap in configMapList:
                    if configMap['metadata']['name'] == valueFrom['valueFrom']['configMapKeyRef']['name'] and configMap['metadata']['namespace'] == job['metadata']['namespace']:
                        resourceMap.append(configMap)
            elif valueFrom.get('valueFrom', {}).get('secretKeyRef', {}):
                for secret in secretList:
                    if secret['metadata']['name'] == valueFrom['valueFrom']['secretKeyRef']['name'] and secret['metadata']['namespace'] == job['metadata']['namespace']:
                        resourceMap.append(secret)

        for resourceAdded in resourceMap:   # Adds all mapped resources to the list for later processing
            mappedResources.append(resourceAdded)

        with open(os.path.join(outputFolderPath, str(job['metadata']['namespace'])+'_'+str(job['metadata']['name'].replace('-'+job['metadata']['name'].split('-')[-1], '').replace('-job', ''))+'-job.json'), "w") as outputFile:
            json.dump(dictSanitiser(resourceMap), outputFile, indent=4, sort_keys=True) # Output job file with all its mapped resources

print("Individual files created, output folder: " + str(outputFolderPath))


#############################
## Additional Output Files ##
#############################

if externalMappings:
    with open(os.path.join(outputFolderPath, '1.ambassador_External-Mappings.json'), "w") as outputFile:    # Create json file with external mappings which cant be mapped to a service.
        json.dump(dictSanitiser(externalMappings), outputFile, indent=4, sort_keys=True)

if unmappedFilters:
    with open(os.path.join(outputFolderPath, '2.ambassador_Unmapped-Filters.json'), "w") as outputFile:    # Create json file with non "Extermal" Filters which cant be mapped to a service.
        json.dump(dictSanitiser(unmappedFilters), outputFile, indent=4, sort_keys=True)

if outputUnmappedResources:
    firstRun = True
    unmappedResources = []
    for namespace in namespaceList:
        unmappedNamespacedResources = []
        for item in allResources:
            if item not in mappedResources and item['metadata'].get('namespace', "") == namespace['metadata']['name'] and item not in externalMappings and item not in unmappedFilters:
                unmappedNamespacedResources.append(item)
            elif firstRun and item['metadata'].get('namespace', "") == "":
                unmappedResources.append(item)
        with open(os.path.join(outputFolderPath, (namespace['metadata']['name']+'_UNMAPPED-Resources.json')), "w") as outputFile:    # Create json file with unmapped resources
            json.dump(dictSanitiser(unmappedNamespacedResources), outputFile, indent=4, sort_keys=True)
        if firstRun:
            firstRun = False
            with open(os.path.join(outputFolderPath, '3.global_UNMAPPED-Resources.json'), "w") as outputFile:    # Create json file with unmapped resources
                json.dump(dictSanitiser(unmappedResources), outputFile, indent=4, sort_keys=True)
