import json
import os
import time

from google.cloud import pubsub
import google.auth

from micromanager import MicroManager
from micromanager.resources import Resource

from stackdriver import StackdriverParser
from logger import Logger

# Load configuration
project_id = os.environ.get('PROJECT_ID')
subscription_name = os.environ.get('SUBSCRIPTION_NAME')
opa_url = os.environ.get('OPA_URL')
enforce_policy = os.environ.get('ENFORCE', '').lower() == 'true'
enforcement_delay = int(os.environ.get('ENFORCEMENT_DELAY', 0))
stackdriver_logging = os.environ.get('STACKDRIVER_LOGGING', '').lower() == 'true'

# We're using the application default credentials, but defining them
# explicitly so its easy to plug-in credentials using your own preferred
# method
app_creds, _ = google.auth.default()

# Instantiate our micromanager
mmconfig = {
    'policy_engines': [
        {
            'type': 'opa',
            'url': opa_url
        }
    ]
}

mm = MicroManager(mmconfig)

logger = Logger('forseti-policy-enforcer', stackdriver_logging, project_id, app_creds)

running_config = {
    'configured_policies': mm.get_configured_policies(),
    'policy_enforcement': "enabled" if enforce_policy else "disabled",
    'stackdriver_logging': "enabled" if stackdriver_logging else "disabled",
    'enforcement_delay': enforcement_delay
}
logger(running_config)


def callback(pubsub_message):
    log = {}

    try:
        log_message = json.loads(pubsub_message.data)
        log_id = log['log_id'] = log_message.get('insertId', 'unknown-id')
    except (json.JSONDecodeError, AttributeError):
        # We can't parse the log message, nothing to do here
        logger('Failure loading json, discarding message')
        pubsub_message.ack()
        return

    logger({'log_id': log_id, 'message': 'Received & decoded json message'})

    # normal activity logs have logName in this form:
    #  projects/<p>/logs/cloudaudit.googleapis.com%2Factivity
    # data access logs have a logName field that looks like:
    #  projects/<p>/logs/cloudaudit.googleapis.com%2Fdata_access
    #
    # try to only handle the normal activity logs
    log_name_end = log_message.get('logName', '').split('/')[-1]
    if log_name_end != 'cloudaudit.googleapis.com%2Factivity':
        logger({'log_id': log_id, 'message': 'Not an activity log, discarding'})
        pubsub_message.ack()
        return

    try:
        asset_info = StackdriverParser.get_asset(log_message)
    except Exception as e:
        # If we fail to get asset info from the message, the message must be
        # bad
        logger({'log_id': log_id,
                'message': 'Exception while parsing message for asset details',
                'details': str(e)})
        pubsub_message.ack()
        return

    log['asset_info'] = asset_info

    if asset_info is None:
        # We did not recognize any assets in this message
        logger({'log_id': log_id,
                'message': 'No recognizable asset info, discarding message'})
        pubsub_message.ack()
        return

    if asset_info.get('operation_type') != 'write':
        # No changes, no need to check anything
        logger({'log_id': log_id,
                'message': 'Message is not a create/update, nothing to do'})
        pubsub_message.ack()
        return

    try:
        resource = Resource.factory('gcp', asset_info, credentials=app_creds)
    except Exception as e:
        logger({'log_id': log_id,
                'message': 'Internal failure in micromanager',
                'details': str(e)})
        pubsub_message.ack()
        return

    logger({'log_id': log_id,
            'message': 'Analyzing for violations'})
    try:
        v = mm.violations(resource)
        log['violation_count'] = len(v)
        log['remediation_count'] = 0
    except Exception as e:
        logger({'log_id': log_id,
                'message': 'Execption while checking for violations',
                'details': str(e)})

    if not enforce_policy:
        logger({'log_id': log_id,
                'message': 'Enforcement is disabled, processing complete'})
        pubsub_message.ack()
        return

    if enforcement_delay:
        logger({'log_id': log_id,
                'message': 'Delaying enforcement by %d seconds' % enforcement_delay})
        time.sleep(enforcement_delay)

    try:
        for (engine, violation) in v:
            logger({'log_id': log_id, 'message': 'Executing remediation'})

            engine.remediate(resource, violation)
            log['remediation_count'] += 1

    except Exception as e:
        # Catch any other exceptions so we can acknowledge the message.
        # Otherwise they start to fill up the buffer of unacknowledged messages
        logger({'log_id': log_id,
                'message': 'Exception while attempting remediation',
                'details': str(e)})
        log['exception'] = str(e)
        pubsub_message.ack()

        # Now allow the thread to raise the exception
        raise e

    logger(log)
    pubsub_message.ack()


if __name__ == "__main__":

    subscriber = pubsub.SubscriberClient(credentials=app_creds)

    subscription_path = 'projects/{project_id}/subscriptions/{sub}'.format(
        project_id=project_id,
        sub=subscription_name
    )

    future = subscriber.subscribe(
        subscription_path,
        callback=callback
    )

    logger("Listening for pubsub messages on {}...".format(subscription_path))

    try:
        future.result()
    except Exception:
        future.cancel()
        raise
