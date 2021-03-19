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
import json
from rpe.resources.gcp import GoogleAPIResource

from .models import ParsedMessage


class StackdriverParser():
    ''' A collection of functions for parsing Stackdriver log messages '''

    @classmethod
    def match(cls, message):

        try:
            message_data = json.loads(message.data)
        except (json.JSONDecodeError, AttributeError):
            return False

        log_type = jmespath.search('protoPayload."@type"', message_data)
        log_name = message_data.get('logName', '')

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
    def parse_message(cls, message):

        message_data = json.loads(message.data)
        publish_timestamp = int(message.publish_time.timestamp())
        metadata = cls._get_metadata(message_data)

        # Only return resources if something changed
        resources = []
        if metadata.get('operation') == 'write':
            resources = cls.get_resources(message_data)

        return ParsedMessage(
            metadata=metadata,
            resources=resources,
            timestamp=cls._get_timestamp(message_data) or publish_timestamp
        )

    @classmethod
    def _get_timestamp(cls, message_data):
        log_time_str = message_data.get('timestamp')
        if log_time_str:
            return int(dateutil.parser.parse(log_time_str).timestamp())

        return None

    @classmethod
    def _get_metadata(cls, message_data):
        log_id = message_data.get('insertId', 'unknown-id')
        log_timestamp = cls._get_timestamp(message_data)

        method_name = jmespath.search('protoPayload.methodName', message_data)
        operation_type = cls._operation_type(message_data)

        return {
            'id': log_id,
            'timestamp': log_timestamp,
            'operation': operation_type,
            'method_name': method_name,
            'src': 'stackdriver-parser',
        }

    @classmethod
    def get_resources(cls, log_message):
        asset_info = cls._extract_asset_info(log_message)

        return [GoogleAPIResource.from_resource_data(**i) for i in asset_info]

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
                'resource_type': 'sqladmin.googleapis.com/Instance',

                # CloudSQL logs are inconsistent. See https://issuetracker.google.com/issues/137629452
                'name': (prop('resource.labels.database_id').split(':')[-1] or
                         prop('protoPayload.request.body.name') or
                         prop('protoPayload.request.resource.instanceName.instanceId')),

                'location': prop('resource.labels.region'),
                'project_id': prop('resource.labels.project_id'),
            }
            add_resource()

        elif res_type == "gcs_bucket" and method_name.startswith(('storage.buckets', 'storage.setIamPermissions')):
            resource_data = {
                'resource_type': 'storage.googleapis.com/Bucket',
                'name': prop("resource.labels.bucket_name"),
                'location': prop("resource.labels.location"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "bigquery_dataset":
            if "DatasetService" in method_name or 'SetIamPolicy' in method_name:
                resource_data = {
                    'resource_type': 'bigquery.googleapis.com/Dataset',
                    'name': prop("resource.labels.dataset_id"),
                    'project_id': prop("resource.labels.project_id"),
                }
                add_resource()

        elif res_type == "project" and method_name == 'SetIamPolicy':
            resource_data = {
                'resource_type': 'cloudresourcemanager.googleapis.com/Project',
                'name': prop("resource.labels.project_id"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "pubsub_subscription" and 'SetIamPolicy' in method_name:
            resource_data = {
                'resource_type': 'pubsub.googleapis.com/Subscription',
                'name': prop("resource.labels.subscription_id").split('/')[-1],
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "pubsub_topic" and 'SetIamPolicy' in method_name:
            resource_data = {
                'resource_type': 'pubsub.googleapis.com/Topic',
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
                'resource_type': 'serviceusage.googleapis.com/Service',
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
                'resource_type': 'serviceusage.googleapis.com/Service',
                'name': prop("resource.labels.service"),
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "gce_subnetwork":
            resource_data = {
                'resource_type': 'compute.googleapis.com/Subnetwork',
                'name': prop("resource.labels.subnetwork_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()

        elif res_type == "gce_firewall_rule":
            resource_data = {
                'resource_type': 'compute.googleapis.com/Firewall',
                'name': prop("protoPayload.resourceName").split('/')[-1],
                'project_id': prop("resource.labels.project_id"),
            }
            add_resource()

        elif res_type == "gae_app" and 'DebugInstance' in method_name:
            instance_data = prop("protoPayload.resourceName").split('/')
            resource_data = {
                'resource_type': 'appengine.googleapis.com/Instance',
                'name': instance_data[-1],
                'app': instance_data[1],
                'service': instance_data[3],
                'version': instance_data[5],
            }
            add_resource()

        elif res_type == "gce_instance":

            resource_data = {
                'resource_type': 'compute.googleapis.com/Instance',
                'name': prop("protoPayload.resourceName").split('/')[-1],
                'location': prop("resource.labels.zone"),
                'project_id': prop("resource.labels.project_id"),
            }

            # Logs are sent for some resources that are hidden by the compute API. We've found that some of these
            # start with reserved prefixes. So if we see them we can safely assume we cant retrieve them
            compute_reserved_prefixes = ('aef-', 'aet-')
            if not resource_data['name'].startswith(compute_reserved_prefixes):
                add_resource()

            # Also add the disk as a resource since theres not a separate log message for these
            disk_name = prop("protoPayload.request.disks[?boot].diskName | [0]")

            resource_data = {
                'resource_type': 'compute.googleapis.com/Disk',
                'name': disk_name or prop("protoPayload.resourceName").split('/')[-1],
                'location': prop("resource.labels.zone"),
                'project_id': prop("resource.labels.project_id"),
            }

            if not resource_data['name'].startswith(compute_reserved_prefixes):
                add_resource()

        elif res_type == "cloud_function":
            resource_data = {
                'name': prop("resource.labels.function_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.region"),
                'resource_type': 'cloudfunctions.googleapis.com/CloudFunction',
            }

            add_resource()

        elif res_type == "cloud_dataproc_cluster":
            resource_data = {
                'resource_type': 'dataproc.googleapis.com/Cluster',
                'project_id': prop("resource.labels.project_id"),
                'name': prop("resource.labels.cluster_name"),
                'location': prop("resource.labels.region"),
            }
            add_resource()

        elif res_type == "gke_cluster":
            resource_data = {
                'resource_type': 'container.googleapis.com/Cluster',
                'name': prop("resource.labels.cluster_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()

            # add node pool resources for eval on new cluster creation
            if "create" in method_name.lower() and prop("protoPayload.request.cluster.nodePools") is not None:
                resource_data['resource_type'] = 'container.googleapis.com/NodePool'
                resource_data['cluster'] = prop("resource.labels.cluster_name")
                for pool in prop("protoPayload.request.cluster.nodePools"):
                    resource_data['name'] = pool.get('name')
                    add_resource()

        elif res_type == "gke_nodepool":
            resource_data = {
                'resource_type': 'container.googleapis.com/NodePool',
                'cluster': prop("resource.labels.cluster_name"),
                'name': prop("resource.labels.nodepool_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()

        elif res_type == "audited_resource" and 'BigtableInstanceAdmin' in method_name:
            resource_data = {
                'name': prop("protoPayload.resourceName").split('/')[-1],
                'project_id': prop("resource.labels.project_id"),
            }

            resource_data['resource_type'] = 'bigtableadmin.googleapis.com/Instance'
            add_resource()

        elif res_type == "dataflow_step" and 'create' in method_name:
            resource_data = {
                'name': prop("protoPayload.request.job_name"),
                'project_id': prop("protoPayload.resource.labels.project_id"),
                'location': prop("protoPayload.resource.labels.region"),
            }

            resource_data['resource_type'] = 'dataflow.googleapis.com/Job'
            add_resource()

        return resources
