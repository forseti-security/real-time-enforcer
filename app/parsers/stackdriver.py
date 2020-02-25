# Copyright 2019 The Forseti Real Time Enforcer Authors. All rights reserved.
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


import dateutil.parser
import jmespath
import time
from rpe.resources.gcp import GoogleAPIResource

from .base import ParsedMessage


class StackdriverParser():
    ''' A collection of functions for parsing Stackdriver log messages '''

    @classmethod
    def match(cls, message):
        log_type = jmespath.search('protoPayload."@type"', message)
        log_name = message.get('logName', '')

        # normal activity logs have logName in this form:
        #  projects/<p>/logs/cloudaudit.googleapis.com%2Factivity
        # data access logs have a logName field that looks like:
        #  projects/<p>/logs/cloudaudit.googleapis.com%2Fdata_access
        #
        # try to only handle the normal activity logs
        return all([
            log_type == 'type.googleapis.com/google.cloud.audit.AuditLog',
            log_name.split('/')[-1] == 'cloudaudit.googleapis.com%2Factivity',
        ])

    @classmethod
    def parse_message(cls, message_data):

        metadata = cls._get_metadata(message_data)

        # Only return resources if something changed
        resources = []
        if metadata.get('operation') == 'write':
            resources = cls.get_resources(message_data)

        return ParsedMessage(metadata=metadata, resources=resources)

    @classmethod
    def _get_metadata(cls, message_data):
        log_id = message_data.get('insertId', 'unknown-id')
        log_time_str = message_data.get('timestamp')
        if log_time_str:
            log_timestamp = int(dateutil.parser.parse(log_time_str).timestamp())
        else:
            log_timestamp = int(time.time())

        message_age = int(time.time()) - log_timestamp

        method_name = jmespath.search('protoPayload.methodName', message_data)
        operation_type = cls._operation_type(message_data)

        return {
            'id': log_id,
            'timestamp': log_timestamp,
            'operation': operation_type,
            'method_name': method_name,
            'message_age': message_age,
        }

    @classmethod
    def get_resources(cls, log_message):
        asset_info = cls._extract_asset_info(log_message)

        return [GoogleAPIResource.factory(**i) for i in asset_info]

    @classmethod
    def _operation_type(cls, message_data):
        ''' We only care about _events_ that alter assets. Maintaining this
        list is going to be annoying. Long term, this entire class  should be
        replaced when google provides a real-time event delivery solution '''

        method_name = jmespath.search('protoPayload.methodName', message_data) or ''

        last = method_name.split('.')[-1].lower()
        # For batch methods, look for the verb after the word 'batch'
        if last.startswith('batch'):
            last = last[5:]

        read_prefixes = ('get', 'list')
        if last.startswith(read_prefixes):
            return 'read'

        write_prefixes = (
            'create',
            'update',
            'insert',
            'patch',
            'set',
            'debug',
            'enable',
            'disable',
            'expand',
            'deactivate',
            'activate'
        )

        if last.startswith(write_prefixes):
            return 'write'

        delete_prefixes = ('delete')
        if last.startswith(delete_prefixes):
            return 'delete'

        else:
            return 'unknown'

    @classmethod
    def _extract_asset_info(cls, message):
        ''' Takes a decoded stackdriver AuditLog message and returns information
        about the asset(s) it references. '''

        resources = []

        res_type = jmespath.search('resource.type', message)
        if res_type is None:
            return resources

        # just shortening the many calls to jmespath throughout this function
        # this sub-function saves us from passing the message each time
        def prop(exp):
            return jmespath.search(exp, message)

        def add_resource():
            r = resource_data.copy()
            resources.append(r)

        method_name = prop('protoPayload.methodName')

        if res_type == 'cloudsql_database' and method_name.startswith('cloudsql.instances'):

            resource_data = {
                'resource_type': 'sqladmin.instances',

                # CloudSQL logs are inconsistent. See https://issuetracker.google.com/issues/137629452
                'name': (prop('resource.labels.database_id').split(':')[-1] or
                         prop('protoPayload.request.body.name') or
                         prop('protoPayload.request.resource.instanceName.instanceId')),

                'location': prop('resource.labels.region'),
                'project_id': prop('resource.labels.project_id'),
            }
            add_resource()

        elif res_type == "gcs_bucket" and method_name.startswith('storage.buckets'):
            resource_data = {
                'resource_type': 'storage.buckets',
                'name': prop("resource.labels.bucket_name"),
                'location': prop("resource.labels.location"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

            # If ACLs are updated, they are scanned by the IAM scanner, but
            # they come through as a bucket update, we need to return both resource types
            resource_data['resource_type'] = 'storage.buckets.iam'
            add_resource()

        elif res_type == "gcs_bucket" and method_name == 'storage.setIamPermissions':
            resource_data = {
                'resource_type': 'storage.buckets.iam',
                'name': prop("resource.labels.bucket_name"),
                'location': prop("resource.labels.location"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "bigquery_dataset":
            if "DatasetService" in method_name or 'SetIamPolicy' in method_name:
                resource_data = {
                    'resource_type': 'bigquery.datasets',
                    'name': prop("resource.labels.dataset_id"),
                    'project_id': prop("resource.labels.project_id"),
                }
                add_resource()

        elif res_type == "project" and method_name == 'SetIamPolicy':
            resource_data = {
                'resource_type': 'cloudresourcemanager.projects.iam',
                'name': prop("resource.labels.project_id"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "pubsub_subscription" and 'SetIamPolicy' in method_name:
            resource_data = {
                'resource_type': 'pubsub.projects.subscriptions.iam',
                'name': prop("resource.labels.subscription_id").split('/')[-1],
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "pubsub_topic" and 'SetIamPolicy' in method_name:
            resource_data = {
                'resource_type': 'pubsub.projects.topics.iam',
                'name': prop("resource.labels.topic_id").split('/')[-1],
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == 'audited_resource' and (
            'EnableService' in method_name or
            'DisableService' in method_name or
            'ctivateService' in method_name
        ):

            resource_data = {
                'resource_type': 'serviceusage.services',
                'project_id': prop("resource.labels.project_id"),
            }

            # Check if multiple services were included in the request
            # The Google Cloud Console generates (De)activate calls that logs a different format so we check both
            # known formats
            services = prop('protoPayload.request.serviceIds') or prop('protoPayload.request.serviceNames')
            if services:
                for s in services:
                    resource_data['name'] = s
                    add_resource()
            else:
                resource_data['name'] = prop("protoPayload.resourceName").split('/')[-1]
                add_resource()

        elif res_type == 'audited_resource' and 'DeactivateServices' in method_name:
            resource_data = {
                'resource_type': 'serviceusage.services',
                'name': prop("resource.labels.service"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "gce_subnetwork":
            resource_data = {
                'resource_type': 'compute.subnetworks',
                'name': prop("resource.labels.subnetwork_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()

        elif res_type == "gce_firewall_rule":
            resource_data = {
                'resource_type': 'compute.firewalls',
                'name': prop("protoPayload.resourceName").split('/')[-1],
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "gae_app" and 'DebugInstance' in method_name:
            instance_data = prop("protoPayload.resourceName").split('/')
            resource_data = {
                'resource_type': 'apps.services.versions.instances',
                'name': instance_data[-1],
                'app': instance_data[1],
                'service': instance_data[3],
                'version': instance_data[5],
            }
            add_resource()

        elif res_type == "gce_instance":
            # gce instance return us result images whitch doesn't contains the source_image part.
            # so we check source_image through the disk resource
            disk_name = prop("protoPayload.request.disks[?boot].diskName | [0]")

            resource_data = {
                'resource_type': 'compute.disks',
                'name': disk_name or prop("protoPayload.resourceName").split('/')[-1],
                'location': prop("resource.labels.zone"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "cloud_function":
            resource_data = {
                'name': prop("resource.labels.function_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.region"),
                'resource_type': 'cloudfunctions.projects.locations.functions',
            }

            if 'SetIamPolicy' in method_name:
                resource_data['resource_type'] = 'cloudfunctions.projects.locations.functions.iam'
            else:
                resource_data['resource_type'] = 'cloudfunctions.projects.locations.functions'
                add_resource()
                resource_data['resource_type'] = 'cloudfunctions.projects.locations.functions.iam'
            add_resource()

        elif res_type == "cloud_dataproc_cluster":
            resource_data = {
                'resource_type': 'dataproc.clusters',
                'project_id': prop("resource.labels.project_id"),
                'name': prop("resource.labels.cluster_name"),
                'location': prop("resource.labels.region"),
            }
            add_resource()

        elif res_type == "gke_cluster":
            resource_data = {
                'resource_type': 'container.projects.locations.clusters',
                'name': prop("resource.labels.cluster_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()

            # add node pool resources for eval on new cluster creation
            if "create" in method_name.lower() and prop("protoPayload.request.cluster.nodePools") is not None:
                resource_data['resource_type'] = 'container.projects.locations.clusters.nodePools'
                resource_data['cluster'] = prop("resource.labels.cluster_name")
                for pool in prop("protoPayload.request.cluster.nodePools"):
                    resource_data['name'] = pool.get('name')
                    add_resource()

        elif res_type == "gke_nodepool":
            resource_data = {
                'resource_type': 'container.projects.locations.clusters.nodePools',
                'cluster': prop("resource.labels.cluster_name"),
                'name': prop("resource.labels.nodepool_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()

            # if nodepool image was updated, add cluster resource for re-evaluation
            if "update" in method_name.lower():
                resource_data['resource_type'] = 'container.projects.locations.clusters'
                resource_data['name'] = prop("resource.labels.cluster_name")
                add_resource()

        elif res_type == "audited_resource" and 'BigtableInstanceAdmin' in method_name:
            resource_data = {
                'name': prop("protoPayload.resourceName").split('/')[-1],
                'project_id': prop("resource.labels.project_id"),
            }

            if 'SetIamPolicy' in method_name:
                resource_data['resource_type'] = 'bigtableadmin.projects.instances.iam'
            else:
                resource_data['resource_type'] = 'bigtableadmin.projects.instances'
                add_resource()
                resource_data['resource_type'] = 'bigtableadmin.projects.instances.iam'
            add_resource()

        return resources