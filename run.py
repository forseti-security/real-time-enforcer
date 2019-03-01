import jmespath
import json
import os
import time

from google.cloud import pubsub
import google.auth

from micromanager import MicroManager
from micromanager.resources import Resource

# Load some environment variables
PROJECT_ID = os.environ.get('PROJECT_ID')
SUBSCRIPTION_NAME = os.environ.get('SUBSCRIPTION_NAME')
OPA_URL = os.environ.get('OPA_URL')

# Instantiate our micromanager
mmconfig = {
    'policy_engines': [
        {
            'type': 'opa',
            'url': OPA_URL
        }
    ]
}

mm = MicroManager(mmconfig)


# Define some exceptions we expect to see
class UnrecognizedResourceTypeError(Exception):
    pass


class ResourceTypeNotFoundError(Exception):
    pass


def log_to_resource(log_message, **kargs):
    ''' Takes a Pub/Sub message and returns a resource if the resource type is
    recognized and supported. Any keyword args will be passed to the resource
    constructor  '''

    map_log_messsge_to_resource_data = {
            "cloudsql_database": {
                    "resource_type": [
                        "resource.type",
                        lambda x: 'sqladmin.instances'
                    ],
                    "resource_name": [
                        "resource.labels.database_id",
                        lambda x: x.split(':')[-1]
                    ],
                    "resource_location": "resource.labels.region",
                    "project_id": "resource.labels.project_id"
            },
            "gcs_bucket": {
                    "resource_type": [
                        "resource.type",
                        lambda x: 'storage.buckets'
                    ],
                    "resource_name": "resource.labels.bucket_name",
                    "resource_location": "resource.labels.location",
                    "project_id": "resource.labels.project_id"
            },
            "bigquery_dataset": {
                    "resource_type": [
                        "resource.type",
                        lambda x: 'bigquery.datasets'
                    ],
                    "resource_name": "resource.labels.dataset_id",
                    "project_id": "resource.labels.project_id"
            },
            "bigquery_resource": {
                    "resource_type": [
                        "resource.type",
                        lambda x: 'bigquery.datasets'
                    ],
                    "resource_name": "resource.labels",
                    "project_id": "resource.labels.project_id"
            }
    }

    try:
        m = json.loads(log_message)
    except json.JSONDecodeError as e:
        # If its not valid JSON, we can't proceed
        raise e

    resource_type = jmespath.search('resource.type', m)
    if resource_type is None:
        raise ResourceTypeNotFoundError()

    # Just grouping the formatting code into a sub function
    def format_data(resource_type, m):
        resource_data = {}

        if resource_type not in map_log_messsge_to_resource_data:
            raise UnrecognizedResourceTypeError()
        resource_data_map = map_log_messsge_to_resource_data[resource_type]

        for key in resource_data_map:
            path = resource_data_map[key]

            # Sometimes we need to parse a string to get the data we need so we
            # support passing a function to parse the jmespath result before
            # returning it
            if isinstance(path, list):
                path, func = path
                resource_data[key] = func(jmespath.search(path, m))
            else:
                resource_data[key] = jmespath.search(path, m)

        return resource_data

    data = format_data(resource_type, m)

    return Resource.factory('gcp', data, **kargs)


def callback(message):

    log = {}
    try:
        resource = log_to_resource(message.data)
        log['resource'] = resource.resource_data
    except (
        json.JSONDecodeError,
        UnrecognizedResourceTypeError,
        ResourceTypeNotFoundError
    ):
        # These exceptions are expected for messages that don't appear to be
        # valid AuditLog entries. We acknowledge the messages and move on.
        message.ack()
        return

    
    # If we were able to find a resource, now we can check policy
    try:
        v = mm.violations(resource)
        log['violation_count'] = len(v)
        log['remediation_count'] = 0

        for (engine, violation) in v:
            engine.remediate(resource, violation)
            log['remediation_count'] += 1


    except Exception as e:
        # Catch any other exceptions so we can acknowledge the message.
        # Otherwise they start to fill up the buffer of unacknowledged messages
        log['exception'] = str(e)
        message.ack()

        # Now allow the thread to raise the exception
        raise e
    finally:
        print(json.dumps(log, separators=(',', ':')))
        message.ack()


if __name__ == "__main__":

    # We're using the application default credentials, but defining them
    # explicitly so its easy to plug-in credentials using your own preferred
    # method
    app_creds, _ = google.auth.default()

    subscriber = pubsub.SubscriberClient(credentials=app_creds)

    subscription_path = 'projects/{project_id}/subscriptions/{sub}'.format(
        project_id=PROJECT_ID,
        sub=SUBSCRIPTION_NAME
    )

    future = subscriber.subscribe(
        subscription_path,
        callback=callback
    )

    print("Listening for pubsub messages on {}...".format(subscription_path))

    try:
        future.result()
    except Exception:
        future.cancel()
        raise
