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
import json
import os
import time

from google.cloud import pubsub

from rpe import RPE
from rpe.resources import Resource

from lib.stackdriver import StackdriverParser
from lib.logger import Logger
from lib.credentials import CredentialsBroker

# Load configuration
app_name = os.environ.get('APP_NAME', 'forseti-realtime-enforcer')
project_id = os.environ.get('PROJECT_ID')
subscription_name = os.environ.get('SUBSCRIPTION_NAME')
opa_url = os.environ.get('OPA_URL')
enforce_policy = os.environ.get('ENFORCE', '').lower() == 'true'
enforcement_delay = int(os.environ.get('ENFORCEMENT_DELAY', 0))
stackdriver_logging = os.environ.get('STACKDRIVER_LOGGING', '').lower() == 'true'
per_project_logging = os.environ.get('PER_PROJECT_LOGGING', '').lower() == 'true'
debug_logging = os.environ.get('DEBUG_LOGGING', '').lower() == 'true'

# We're using the application default credentials, but defining them
# explicitly so its easy to plug-in credentials using your own preferred
# method
cb = CredentialsBroker()
app_creds = cb.get_credentials()

# Setup logging helper
logger = Logger(
    app_name,
    stackdriver_logging,
    project_id,
    app_creds,
    debug_logging
)

# Instantiate our rpe
rpeconfig = {
    'policy_engines': [
        {
            'type': 'opa',
            'url': opa_url
        }
    ]
}

rpe = RPE(rpeconfig)

running_config = {
    'configured_policies': rpe.get_configured_policies(),
    'policy_enforcement': "enabled" if enforce_policy else "disabled",
    'stackdriver_logging': "enabled" if stackdriver_logging else "disabled",
    'enforcement_delay': enforcement_delay,
    'debug_logging': "enabled" if debug_logging else "disabled"
}
logger(running_config)


def callback(pubsub_message):

    try:
        log_message = json.loads(pubsub_message.data)
        log_id = log_message.get('insertId', 'unknown-id')

        # Get the timestamp from the log message
        log_time_str = log_message.get('timestamp')
        if log_time_str:
            log_timestamp = int(dateutil.parser.parse(log_time_str).timestamp())
        else:
            log_timestamp = int(time.time())

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
            logger.debug({
                'log_id': log_id,
                'message': 'Message is not a create/update, nothing to do'}
            )
            pubsub_message.ack()
            continue

        try:
            project_creds = cb.get_credentials(project_id=asset_info['project_id'])
            if per_project_logging:
                project_logger = Logger(
                    app_name,
                    True,  # per-project logging is always stackdriver
                    asset_info['project_id'],
                    project_creds
                )
            resource = Resource.factory('gcp', asset_info, credentials=project_creds)
        except Exception as e:
            logger.debug({
                'log_id': log_id,
                'message': 'Internal failure in rpe-lib',
                'details': str(e)
            })
            pubsub_message.ack()
            continue

        logger.debug({
            'log_id': log_id,
            'message': 'Analyzing for violations'
        })

        try:
            v = rpe.violations(resource)
            log['violation_count'] = len(v)
            log['remediation_count'] = 0
        except Exception as e:
            logger.debug({
                'log_id': log_id,
                'message': 'Execption while checking for violations',
                'details': str(e)
            })
            continue

        if not enforce_policy:
            logger.debug({
                'log_id': log_id,
                'message': 'Enforcement is disabled, processing complete'
            })
            pubsub_message.ack()
            continue

        if enforcement_delay:
            # If the log is old, subtract that from the enforcement delay
            message_age = int(time.time()) - log_timestamp
            log['message_age'] = message_age
            delay = max(0, enforcement_delay - message_age)
            logger.debug({
                'log_id': log_id,
                'message': 'Delaying enforcement by %d seconds, message is already %d seconds old and our configured delay is %d seconds' % (delay, message_age, enforcement_delay)
            })
            time.sleep(delay)

        for (engine, violation) in v:
            logger.debug({'log_id': log_id, 'message': 'Executing remediation'})

            try:
                engine.remediate(resource, violation)
                log['remediation_count'] += 1

                if per_project_logging:
                    project_log = {
                        'event': 'remediation',
                        'trigger_event': asset_info,
                        'policy': str(violation)
                    }
                    project_logger(project_log)

            except Exception as e:
                # Catch any other exceptions so we can acknowledge the message.
                # Otherwise they start to fill up the buffer of unacknowledged messages
                logger({'log_id': log_id,
                        'message': 'Exception while attempting remediation of {}'.format(violation),
                        'details': str(e)})

                if 'exceptions' not in log:
                    log['exceptions'] = []

                log['exceptions'].append(str(e))

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
