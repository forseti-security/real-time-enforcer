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
    def get_asset(cls, log_message):
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

        l = method_name.split('.')[-1]
        if l in ['list', 'get', 'List']:
            return 'read'

        if l in ['create', 'update', 'InsertDataset', 'PatchDataset', 'setIamPermissions', 'SetIamPolicy']:
            return 'write'

        if l in ['delete']:
            return 'delete'

        else:
            return 'unknown'



    @classmethod
    def _extract_asset_info(cls, res_type, message):

        # just shortening the many calls to jmespath throughout this function
        # this sub-function saves us from passing the message each time
        def prop(exp):
            return jmespath.search(exp, message)

        method_name = prop('protoPayload.methodName')
        operation_type = cls._operation_type(res_type, method_name)

        if res_type == 'cloudsql_database' and method_name.startswith('cloudsql.instances'):
            resource_type = 'sqladmin.instances'
            resource_name = prop('resource.labels.database_id').split(':')[-1]
            resource_location = prop('resource.labels.region')
            project_id = prop('resource.labels.project_id')

        elif res_type == "gcs_bucket" and method_name.startswith('storage.buckets'):
            resource_type = 'storage.buckets'
            resource_name = prop("resource.labels.bucket_name")
            resource_location = prop("resource.labels.location")
            project_id = prop("resource.labels.project_id")

        elif res_type == "gcs_bucket" and method_name == 'storage.setIamPermissions':
            resource_type = 'storage.buckets.iam'
            resource_name = prop("resource.labels.bucket_name")
            resource_location = prop("resource.labels.location")
            project_id = prop("resource.labels.project_id")

        elif res_type == "bigquery_dataset":
            if "DatasetService" in method_name or 'SetIamPolicy' in method_name:
                resource_type = 'bigquery.datasets'
                resource_name = prop("resource.labels.dataset_id")
                resource_location = ''
                project_id = prop("resource.labels.project_id")

        elif res_type == "project" and method_name == 'SetIamPolicy':
            resource_type = 'cloudresourcemanager.projects.iam'
            resource_name = prop("resource.labels.project_id")
            resource_location = ''
            project_id = prop("resource.labels.project_id")
        else:
            return None

        return {
            'resource_type': resource_type,
            'resource_name': resource_name,
            'resource_location': resource_location,
            'project_id': project_id,
            'method_name': method_name,
            'operation_type': operation_type
        }
