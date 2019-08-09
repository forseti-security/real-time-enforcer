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
        read_prefixes = ('get', 'list')
        if last.startswith(read_prefixes):
            return 'read'

        write_prefixes = ('create', 'update', 'insert', 'patch', 'set', 'activate', 'deactivate')
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
            resources.append({
                'resource_type': resource_type,
                'resource_name': resource_name,
                'resource_location': resource_location,
                'project_id': project_id,
                'method_name': method_name,
                'operation_type': operation_type
            })

        method_name = prop('protoPayload.methodName')
        operation_type = cls._operation_type(res_type, method_name)

        if res_type == 'cloudsql_database' and method_name.startswith('cloudsql.instances'):
            resource_type = 'sqladmin.instances'

            # CloudSQL logs are inconsistent. See https://issuetracker.google.com/issues/137629452
            resource_name = (prop('resource.labels.database_id').split(':')[-1] or
                            prop('protoPayload.request.body.name') or
                            prop('protoPayload.request.resource.instanceName.instanceId'))

            resource_location = prop('resource.labels.region')
            project_id = prop('resource.labels.project_id')
            add_resource()

        elif res_type == "gcs_bucket" and method_name.startswith('storage.buckets'):
            resource_type = 'storage.buckets'
            resource_name = prop("resource.labels.bucket_name")
            resource_location = prop("resource.labels.location")
            project_id = prop("resource.labels.project_id")
            add_resource()

            # If ACLs are updated, they are scanned by the IAM scanner, but
            # they come through as a bucket update, we need to return both resource types
            resource_type = 'storage.buckets.iam'
            add_resource()

        elif res_type == "gcs_bucket" and method_name == 'storage.setIamPermissions':
            resource_type = 'storage.buckets.iam'
            resource_name = prop("resource.labels.bucket_name")
            resource_location = prop("resource.labels.location")
            project_id = prop("resource.labels.project_id")
            add_resource()

        elif res_type == "bigquery_dataset":
            if "DatasetService" in method_name or 'SetIamPolicy' in method_name:
                resource_type = 'bigquery.datasets'
                resource_name = prop("resource.labels.dataset_id")
                resource_location = ''
                project_id = prop("resource.labels.project_id")
                add_resource()

        elif res_type == "project" and method_name == 'SetIamPolicy':
            resource_type = 'cloudresourcemanager.projects.iam'
            resource_name = prop("resource.labels.project_id")
            resource_location = ''
            project_id = prop("resource.labels.project_id")
            add_resource()

        elif res_type == "pubsub_subscription" and 'SetIamPolicy' in method_name:
            resource_type = 'pubsub.projects.subscriptions.iam'
            resource_name = prop("resource.labels.subscription_id").split('/')[-1]
            project_id = prop("resource.labels.project_id")
            resource_location = ''
            add_resource()

        elif res_type == "pubsub_topic" and 'SetIamPolicy' in method_name:
            resource_type = 'pubsub.projects.topics.iam'
            resource_name = prop("resource.labels.topic_id").split('/')[-1]
            project_id = prop("resource.labels.project_id")
            resource_location = ''
            add_resource()

        elif res_type == 'audited_resource' and 'ActivateServices' in method_name:
            resource_type = 'serviceusage.services'
            resource_name = prop("resource.labels.service")
            project_id = prop("resource.labels.project_id")
            resource_location = ''
            add_resource()

        elif res_type == 'audited_resource' and 'DeactivateServices' in method_name:
            resource_type = 'serviceusage.services'
            resource_name = prop("resource.labels.service")
            project_id = prop("resource.labels.project_id")
            resource_location = ''
            add_resource()

        return resources
