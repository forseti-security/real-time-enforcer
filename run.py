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
debug_logging = os.environ.get('DEBUG_LOGGING', '').lower() == 'true'

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

logger = Logger('forseti-policy-enforcer', stackdriver_logging, project_id, app_creds, debug_logging)

running_config = {
    'configured_policies': mm.get_configured_policies(),
    'policy_enforcement': "enabled" if enforce_policy else "disabled",
    'stackdriver_logging': "enabled" if stackdriver_logging else "disabled",
    'enforcement_delay': enforcement_delay
}
logger(running_config)


def callback(pubsub_message):

    try:
        log_message = json.loads(pubsub_message.data)
        log_id = log_message.get('insertId', 'unknown-id')
    except (json.JSONDecodeError, AttributeError):
        # We can't parse the log message, nothing to do here
        logger.debug('Failure loading json, discarding message')
        pubsub_message.ack()
        return

    logger.debug({'log_id': log_id, 'message': 'Received & decoded json message'})

    # normal activity logs have logName in this form:
    #  projects/<p>/logs/cloudaudit.googleapis.com%2Factivity
    # data access logs have a logName field that looks like:
    #  projects/<p>/logs/cloudaudit.googleapis.com%2Fdata_access
    #
    # try to only handle the normal activity logs
    log_name_end = log_message.get('logName', '').split('/')[-1]
    if log_name_end != 'cloudaudit.googleapis.com%2Factivity':
        logger.debug({'log_id': log_id, 'message': 'Not an activity log, discarding'})
        pubsub_message.ack()
        return

    # Attempt to get a list of asset(s) affected by this event
    try:
        assets = StackdriverParser.get_assets(log_message)

        if len(assets) == 0:
            # We did not recognize any assets in this message
            logger.debug({
                'log_id': log_id,
                'message': 'No recognized assets in log'
            })

            pubsub_message.ack()
            return

    except Exception as e:
        # If we fail to get asset info from the message, the message must be
        # bad
        logger.debug({
            'log_id': log_id,
            'message': 'Exception while parsing message for asset details',
            'details': str(e)
        })

        pubsub_message.ack()
        return

    for asset_info in assets:

        # Start building our log message
        log = {}
        log['log_id'] = log_id
        log['asset_info'] = asset_info

        if asset_info.get('operation_type') != 'write':
            # No changes, no need to check anything
            logger.debug({'log_id': log_id,
                    'message': 'Message is not a create/update, nothing to do'})
            pubsub_message.ack()
            continue

        try:
            resource = Resource.factory('gcp', asset_info, credentials=app_creds)
        except Exception as e:
            logger.debug({'log_id': log_id,
                    'message': 'Internal failure in micromanager',
                    'details': str(e)})
            pubsub_message.ack()
            continue

        logger.debug({'log_id': log_id,
                'message': 'Analyzing for violations'})

        try:
            v = mm.violations(resource)
            log['violation_count'] = len(v)
            log['remediation_count'] = 0
        except Exception as e:
            logger.debug({'log_id': log_id,
                    'message': 'Execption while checking for violations',
                    'details': str(e)})
            continue

        if not enforce_policy:
            logger.debug({'log_id': log_id,
                    'message': 'Enforcement is disabled, processing complete'})
            pubsub_message.ack()
            continue

        if enforcement_delay:
            logger.debug({'log_id': log_id,
                    'message': 'Delaying enforcement by %d seconds' % enforcement_delay})
            time.sleep(enforcement_delay)

        try:
            for (engine, violation) in v:
                logger.debug({'log_id': log_id, 'message': 'Executing remediation'})

                engine.remediate(resource, violation)
                log['remediation_count'] += 1

        except Exception as e:
            # Catch any other exceptions so we can acknowledge the message.
            # Otherwise they start to fill up the buffer of unacknowledged messages
            logger({'log_id': log_id,
                    'message': 'Exception while attempting remediation',
                    'details': str(e)})
            log['exception'] = str(e)

        logger(log)

    # Finally ack the message after we're done with all of the assets
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
