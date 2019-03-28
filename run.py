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
    logger('Received message, begin processing')

    log = {}

    if enforcement_delay:
        logger('Delaying processing by %d seconds' % enforcement_delay)
    time.sleep(enforcement_delay)

    try:
        log_message = json.loads(pubsub_message.data)
        logger('Successfully decoded json message')
    except (json.JSONDecodeError, AttributeError):
        # We can't parse the log message, nothing to do here
        logger('Failure loading json, discarding message')
        pubsub_message.ack()
        return

    try:
        asset_info = StackdriverParser.get_asset(log_message)

        if asset_info is None:
            # We did not recognize any assets in this message
            logger('No recognizable asset info, discarding message')
            pubsub_message.ack()
            return

        if asset_info.get('operation_type') != 'write':
            # No changes, no need to check anything
            pubsub_message.ack()
            return

    except Exception:
        # If we fail to get asset info from the message, the message must be
        # bad
        logger('Exception caught while parsing message for asset details')
        pubsub_message.ack()
        return

    try:
        log['asset_info'] = asset_info
        resource = Resource.factory('gcp', asset_info, credentials=app_creds)

        logger('Analyzing for violations')
        v = mm.violations(resource)
        log['violation_count'] = len(v)
        log['remediation_count'] = 0

        if enforce_policy:
            for (engine, violation) in v:
                logger('Executing remediation')
                engine.remediate(resource, violation)
                log['remediation_count'] += 1

    except Exception as e:
        # Catch any other exceptions so we can acknowledge the message.
        # Otherwise they start to fill up the buffer of unacknowledged messages
        logger('Exception caught while searching for violations or attempting remediation, discarding message')
        log['exception'] = str(e)
        pubsub_message.ack()

        # Now allow the thread to raise the exception
        raise e
    finally:
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
