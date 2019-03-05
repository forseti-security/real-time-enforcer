import json
import os

from google.cloud import pubsub
import google.auth

from micromanager import MicroManager
from micromanager.resources import Resource

from stackdriver import StackdriverParser

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


def callback(pubsub_message):

    log = {}

    try:
        log_message = json.loads(pubsub_message.data)
    except (json.JSONDecodeError, AttributeError):
        # We can't parse the log message, nothing to do here
        pubsub_message.ack()
        return

    try:
        asset_info = StackdriverParser.get_asset(log_message)

        if asset_info is None:
            # We did not recognize any assets in this message
            pubsub_message.ack()
            return
    except Exception:
        # If we fail to get asset info from the message, the message must be
        # bad
        pubsub_message.ack()
        return

    try:
        log['asset_info'] = asset_info
        resource = Resource.factory('gcp', asset_info)

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
        pubsub_message.ack()

        # Now allow the thread to raise the exception
        raise e
    finally:
        print(json.dumps(log, separators=(',', ':')))
        pubsub_message.ack()


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
