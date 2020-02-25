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
import traceback

from google.cloud import pubsub

from rpe import RPE

from parsers.stackdriver import StackdriverParser
from parsers.cai import CaiParser
#from parsers.test_parsers import NoMatchParser
#from parsers.test_parsers import MatchExceptionParser
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

# Setup message handlers
message_parsers = [
#    NoMatchParser,
#    MatchExceptionParser,
    CaiParser,
    StackdriverParser,
]

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

    # We use the message ID in all logs we emit
    message_id = pubsub_message.message_id
    message_timestamp = int(pubsub_message.publish_time.timestamp())

    try:
        message_data = json.loads(pubsub_message.data)
    except (json.JSONDecodeError, AttributeError):
        # We can't parse the log message, nothing to do here
        logger.debug({'message_id': message_id, 'message': 'Failure loading json, discarding message'})
        pubsub_message.ack()
        return

    logger.debug({'message_id': message_id, 'message': 'Received & decoded json message'})

    # Only one message parser should be able to parse a given message, lets capture which one it is
    parser_match = None

    for parser in message_parsers:

        try:
            if not parser.match(message_data):
                logger.debug({'message_id': message_id, 'message': f'Message not matched by parser {parser.__name__}'})
                continue

            logger.debug({'message_id': message_id, 'message': f'Message matched by parser {parser.__name__}'})

            parsed_message = parser.parse_message(message_data)
            parser_match = parser

            if len(parsed_message.resources) == 0:
                # We did not recognize any assets in this message
                logger.debug({'message_id': message_id, 'message': f'No resources identified in message parsed by {parser.__name__}', 'metadata': parsed_message.metadata})

                pubsub_message.ack()
                return
            break

        except Exception as e:
            logger({'message_id': message_id, 'message': f'Exception while parsing message with {parser.__name__}', **exc_info(e)})

    # If no message parsers were able to parse the message, log and return
    if parser_match is None:
        logger({'message_id': message_id, 'message': 'No parsers recognized the message format, discarding message'})
        pubsub_message.ack()
        return

    for resource in parsed_message.resources:

        try:

            # Set the resource's credentials before any API calls
            project_creds = cb.get_credentials(project_id=resource.project_id)
            resource.client_kwargs = {
                'credentials': project_creds
            }

            if per_project_logging:
                project_logger = Logger(
                    app_name,
                    True,  # per-project logging is always stackdriver
                    resource.project_id,
                    project_creds
                )

        except Exception as e:
            logger({
                'message_id': message_id,
                'message': 'Internal failure in rpe-lib',
                **exc_info(e),
            })
            pubsub_message.ack()
            continue

        logger.debug({'message_id': message_id, 'message': f'Evaluating resource for violations'})

        # Fetch a list of policies and then violations.  The policy
        # list is needed to log data about evaluated policies that are
        # not violated by the current asset.

        try:
            policies = rpe.policies(resource)
        except Exception as e:
            logger({
                'message_id': message_id,
                'message': 'Exception while retrieving policies',
                **exc_info(e),
            })
            pubsub_message.ack()
            continue

        try:
            violations = rpe.violations(resource)
        except Exception as e:
            logger(dict(
                message='Exception while checking for violations',
                **exc_info(e),
            ))
            continue

        logs = mklogs(message_id, parsed_message.metadata, resource, policies, violations)

        if enforce_policy and parsed_message.control_data.enforce:

            if enforcement_delay and parsed_message.control_data.delay_enforcement:

                delay_timestamp = parsed_message.metadata.get('timestamp') or message_timestamp
                message_age = int(time.time()) - delay_timestamp

                # If the log is old, subtract that from the enforcement delay
                delay = max(0, enforcement_delay - message_age)
                logger.debug({
                    'message_id': message_id,
                    'message': 'Delaying enforcement by %d seconds, message is already %d seconds old and our configured delay is %d seconds' % (delay, message_age, enforcement_delay)
                })
                time.sleep(delay)

            for (engine, violated_policy) in violations:

                logger.debug({'message_id': message_id, 'message': f'Executing remediation'})

                try:
                    engine.remediate(resource, violated_policy)
                    logs[violated_policy]['remediated'] = True
                    logs[violated_policy]['remediated_at'] = int(time.time())

                    if per_project_logging:
                        project_log = {
                            'event': 'remediation',
                            'trigger_event': parsed_message.metadata,
                            'resource_data': resource.to_dict(),
                            'policy': violated_policy,
                        }
                        project_logger(project_log)

                except Exception as e:
                    # Catch any other exceptions so we can acknowledge the message.
                    # Otherwise they start to fill up the buffer of unacknowledged messages
                    logger(dict(
                        message='Execption while attempting to remediate',
                        **exc_info(e),
                    ))

        else:
            logger.debug({'message_id': message_id, 'message': 'Enforcement is disabled, processing complete'})

        for policy in logs:
            logger(logs[policy])

    # Finally ack the message after we're done with all of the assets
    pubsub_message.ack()


def exc_info(exception):
    return {
        'details': str(exception),
        'trace': traceback.format_exc(),
    }


def mklogs(message_id, metadata, resource, policies, violations):
    logs = {}
    violated_policies = {y for x, y in violations}
    evaluated_at = int(time.time())
    resource_data = resource.to_dict()

    for policy in policies:
        logs[policy] = {
            'message_id': message_id,
            'policy': policy,
            'resource_data': resource_data,
            'violation': policy in violated_policies,
            'evaluated_at': evaluated_at,
            'remediated': False,  # will be updated after remediation occurs
            'metadata': metadata,
        }

    return logs


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
