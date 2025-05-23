# -*- coding: utf-8 -*- #
# Copyright 2023 Google LLC. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Resource definitions for Cloud Platform Apis generated from apitools."""

import enum


BASE_URL = 'https://networksecurity.googleapis.com/v1alpha1/'
DOCS_URL = 'https://cloud.google.com/networking'


class Collections(enum.Enum):
  """Collections for all supported apis."""

  ORGANIZATIONS = (
      'organizations',
      'organizations/{organizationsId}',
      {},
      ['organizationsId'],
      True
  )
  ORGANIZATIONS_LOCATIONS = (
      'organizations.locations',
      'organizations/{organizationsId}/locations/{locationsId}',
      {},
      ['organizationsId', 'locationsId'],
      True
  )
  ORGANIZATIONS_LOCATIONS_ADDRESSGROUPS = (
      'organizations.locations.addressGroups',
      '{+name}',
      {
          '':
              'organizations/{organizationsId}/locations/{locationsId}/'
              'addressGroups/{addressGroupsId}',
      },
      ['name'],
      True
  )
  ORGANIZATIONS_LOCATIONS_FIREWALLENDPOINTS = (
      'organizations.locations.firewallEndpoints',
      '{+name}',
      {
          '':
              'organizations/{organizationsId}/locations/{locationsId}/'
              'firewallEndpoints/{firewallEndpointsId}',
      },
      ['name'],
      True
  )
  ORGANIZATIONS_LOCATIONS_OPERATIONS = (
      'organizations.locations.operations',
      '{+name}',
      {
          '':
              'organizations/{organizationsId}/locations/{locationsId}/'
              'operations/{operationsId}',
      },
      ['name'],
      True
  )
  ORGANIZATIONS_LOCATIONS_SECURITYPROFILEGROUPS = (
      'organizations.locations.securityProfileGroups',
      '{+name}',
      {
          '':
              'organizations/{organizationsId}/locations/{locationsId}/'
              'securityProfileGroups/{securityProfileGroupsId}',
      },
      ['name'],
      True
  )
  ORGANIZATIONS_LOCATIONS_SECURITYPROFILES = (
      'organizations.locations.securityProfiles',
      '{+name}',
      {
          '':
              'organizations/{organizationsId}/locations/{locationsId}/'
              'securityProfiles/{securityProfilesId}',
      },
      ['name'],
      True
  )
  PROJECTS = (
      'projects',
      'projects/{projectsId}',
      {},
      ['projectsId'],
      True
  )
  PROJECTS_LOCATIONS = (
      'projects.locations',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_ADDRESSGROUPS = (
      'projects.locations.addressGroups',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/addressGroups/'
              '{addressGroupsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_AUTHORIZATIONPOLICIES = (
      'projects.locations.authorizationPolicies',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'authorizationPolicies/{authorizationPoliciesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_AUTHZPOLICIES = (
      'projects.locations.authzPolicies',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/authzPolicies/'
              '{authzPoliciesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_BACKENDAUTHENTICATIONCONFIGS = (
      'projects.locations.backendAuthenticationConfigs',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'backendAuthenticationConfigs/{backendAuthenticationConfigsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_CLIENTTLSPOLICIES = (
      'projects.locations.clientTlsPolicies',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'clientTlsPolicies/{clientTlsPoliciesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_DNSTHREATDETECTORS = (
      'projects.locations.dnsThreatDetectors',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'dnsThreatDetectors/{dnsThreatDetectorsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_FIREWALLATTACHMENTS = (
      'projects.locations.firewallAttachments',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'firewallAttachments/{firewallAttachmentsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_FIREWALLENDPOINTASSOCIATIONS = (
      'projects.locations.firewallEndpointAssociations',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'firewallEndpointAssociations/{firewallEndpointAssociationsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_GATEWAYATTACHMENTS = (
      'projects.locations.gatewayAttachments',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'gatewayAttachments/{gatewayAttachmentsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_GATEWAYATTACHMENTS_GATEWAYENDPOINTS = (
      'projects.locations.gatewayAttachments.gatewayEndpoints',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'gatewayAttachments/{gatewayAttachmentsId}/gatewayEndpoints/'
              '{gatewayEndpointsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_GATEWAYSECURITYPOLICIES = (
      'projects.locations.gatewaySecurityPolicies',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'gatewaySecurityPolicies/{gatewaySecurityPoliciesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_GATEWAYSECURITYPOLICIES_RULES = (
      'projects.locations.gatewaySecurityPolicies.rules',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'gatewaySecurityPolicies/{gatewaySecurityPoliciesId}/rules/'
              '{rulesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_INTERCEPTDEPLOYMENTGROUPS = (
      'projects.locations.interceptDeploymentGroups',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'interceptDeploymentGroups/{interceptDeploymentGroupsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_INTERCEPTDEPLOYMENTS = (
      'projects.locations.interceptDeployments',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'interceptDeployments/{interceptDeploymentsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_INTERCEPTENDPOINTGROUPASSOCIATIONS = (
      'projects.locations.interceptEndpointGroupAssociations',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'interceptEndpointGroupAssociations/'
              '{interceptEndpointGroupAssociationsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_INTERCEPTENDPOINTGROUPS = (
      'projects.locations.interceptEndpointGroups',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'interceptEndpointGroups/{interceptEndpointGroupsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_MIRRORINGDEPLOYMENTGROUPS = (
      'projects.locations.mirroringDeploymentGroups',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'mirroringDeploymentGroups/{mirroringDeploymentGroupsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_MIRRORINGDEPLOYMENTS = (
      'projects.locations.mirroringDeployments',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'mirroringDeployments/{mirroringDeploymentsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_MIRRORINGENDPOINTGROUPASSOCIATIONS = (
      'projects.locations.mirroringEndpointGroupAssociations',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'mirroringEndpointGroupAssociations/'
              '{mirroringEndpointGroupAssociationsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_MIRRORINGENDPOINTGROUPS = (
      'projects.locations.mirroringEndpointGroups',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'mirroringEndpointGroups/{mirroringEndpointGroupsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_MIRRORINGENDPOINTS = (
      'projects.locations.mirroringEndpoints',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'mirroringEndpoints/{mirroringEndpointsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_OPERATIONS = (
      'projects.locations.operations',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/operations/'
              '{operationsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_PARTNERSSEENVIRONMENTS = (
      'projects.locations.partnerSSEEnvironments',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'partnerSSEEnvironments/{partnerSSEEnvironmentsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_PARTNERSSEGATEWAYS = (
      'projects.locations.partnerSSEGateways',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'partnerSSEGateways/{partnerSSEGatewaysId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_PARTNERSSEREALMS = (
      'projects.locations.partnerSSERealms',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'partnerSSERealms/{partnerSSERealmsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_SACATTACHMENTS = (
      'projects.locations.sacAttachments',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/sacAttachments/'
              '{sacAttachmentsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_SACREALMS = (
      'projects.locations.sacRealms',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/sacRealms/'
              '{sacRealmsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_SECURITYPROFILEGROUPS = (
      'projects.locations.securityProfileGroups',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'securityProfileGroups/{securityProfileGroupsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_SECURITYPROFILES = (
      'projects.locations.securityProfiles',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'securityProfiles/{securityProfilesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_SERVERTLSPOLICIES = (
      'projects.locations.serverTlsPolicies',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'serverTlsPolicies/{serverTlsPoliciesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_SSEGATEWAYREFERENCES = (
      'projects.locations.sseGatewayReferences',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'sseGatewayReferences/{sseGatewayReferencesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_TLSINSPECTIONPOLICIES = (
      'projects.locations.tlsInspectionPolicies',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'tlsInspectionPolicies/{tlsInspectionPoliciesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_ULLMIRRORINGCOLLECTORS = (
      'projects.locations.ullMirroringCollectors',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'ullMirroringCollectors/{ullMirroringCollectorsId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_ULLMIRRORINGENGINES = (
      'projects.locations.ullMirroringEngines',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'ullMirroringEngines/{ullMirroringEnginesId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_ULLMIRRORINGINFRAS = (
      'projects.locations.ullMirroringInfras',
      'projects/{projectsId}/locations/{locationsId}/ullMirroringInfras/'
      '{ullMirroringInfrasId}',
      {},
      ['projectsId', 'locationsId', 'ullMirroringInfrasId'],
      True
  )
  PROJECTS_LOCATIONS_ULLMIRRORINGINFRAS_ULLMIRROREDNETWORKS = (
      'projects.locations.ullMirroringInfras.ullMirroredNetworks',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/'
              'ullMirroringInfras/{ullMirroringInfrasId}/ullMirroredNetworks/'
              '{ullMirroredNetworksId}',
      },
      ['name'],
      True
  )
  PROJECTS_LOCATIONS_URLLISTS = (
      'projects.locations.urlLists',
      '{+name}',
      {
          '':
              'projects/{projectsId}/locations/{locationsId}/urlLists/'
              '{urlListsId}',
      },
      ['name'],
      True
  )

  def __init__(self, collection_name, path, flat_paths, params,
               enable_uri_parsing):
    self.collection_name = collection_name
    self.path = path
    self.flat_paths = flat_paths
    self.params = params
    self.enable_uri_parsing = enable_uri_parsing
