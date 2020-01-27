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


import jmespath


class StackdriverParser():
    ''' A collection of functions for parsing Stackdriver log messages '''

    @classmethod
    def _is_auditlog(cls, message):
        ''' Check whether or not a log message is an audit log '''
        audit_log_type = 'type.googleapis.com/google.cloud.audit.AuditLog'
        message_type = jmespath.search('protoPayload."@type"', message)
        return message_type == audit_log_type

    @classmethod
    def get_assets(cls, log_message):
        ''' Takes a decoded stackdriver AuditLog message and returns information
        about the asset(s) it references. We attempt to return None if we don't
        recognize the asset type '''

        # Right now, this only works for audit log messages
        if not cls._is_auditlog(log_message):
            return None

        # We need to know the resource type
        resource_type = jmespath.search('resource.type', log_message)
        if resource_type is None:
            return None

        data = cls._extract_asset_info(resource_type, log_message)
        return data

    @classmethod
    def _operation_type(cls, res_type, method_name):
        ''' We only care about _events_ that alter assets. Maintaining this
        list is going to be annoying. Long term, this entire class  should be
        replaced when google provides a real-time event delivery solution '''

        last = method_name.split('.')[-1].lower()
        # For batch methods, look for the verb after the word 'batch'
        if last.startswith('batch'):
            last = last[5:]

        read_prefixes = ('get', 'list')
        if last.startswith(read_prefixes):
            return 'read'

        write_prefixes = ('create', 'update', 'insert', 'patch', 'set', 'debug', 'enable', 'disable', 'expand', 'deactivate', 'activate')
        if last.startswith(write_prefixes):
            return 'write'

        delete_prefixes = ('delete')
        if last.startswith(delete_prefixes):
            return 'delete'

        else:
            return 'unknown'

    @classmethod
    def _extract_asset_info(cls, res_type, message):

        resources = []

        # just shortening the many calls to jmespath throughout this function
        # this sub-function saves us from passing the message each time
        def prop(exp):
            return jmespath.search(exp, message)

        def add_resource():
            r = resource_data.copy()
            r.update({
                'method_name': method_name,
                'operation_type': operation_type
            })
            resources.append(r)

        method_name = prop('protoPayload.methodName')
        operation_type = cls._operation_type(res_type, method_name)

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

        elif res_type == 'audited_resource' and ('EnableService' in method_name or 'DisableService' in method_name or 'ctivateService' in method_name):

            resource_data = {
                'resource_type': 'serviceusage.services',
                'project_id': prop("resource.labels.project_id"),
            }

            # Check if multiple services were included in the request
            # The Google Cloud Console generates (De)activate calls that logs a different format so we check both known formats
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
            #gce instance return us result images whitch doesn't contains the source_image part.
            #so we check source_image through the disk resource
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

            ## JPC Note: We should update the policy for this to run on a nodepool

            # if nodepool image was updated, add cluster resource for re-evaluation
            if "update" in method_name.lower():
                resource_data['resource_type'] = 'container.projects.locations.clusters'
                resource_data['name'] =  prop("resource.labels.cluster_name")
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
