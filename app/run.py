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

import os
import time
import traceback

from google.cloud import pubsub

from rpe import RPE

from parsers.stackdriver import StackdriverParser
from parsers.cai import CaiParser
from lib.logger import Logger
from lib.credentials import CredentialsBroker
import hooks

# Load configuration
app_name = os.environ.get('APP_NAME', 'forseti-realtime-enforcer')
project_id = os.environ.get('PROJECT_ID')
subscription_name = os.environ.get('SUBSCRIPTION_NAME')
opa_url = os.environ.get('OPA_URL')
python_policy_path = os.environ.get('PYTHON_POLICY_PATH')
enforce_policy = os.environ.get('ENFORCE', '').lower() == 'true'
enforcement_delay = int(os.environ.get('ENFORCEMENT_DELAY', 0))
stackdriver_logging = os.environ.get('STACKDRIVER_LOGGING', '').lower() == 'true'
per_project_logging = os.environ.get('PER_PROJECT_LOGGING', '').lower() == 'true'
debug_logging = os.environ.get('DEBUG_LOGGING', '').lower() == 'true'

# Build a dict of pubsub flow control settings from env vars if they're set
flow_control_config = {k: int(v) for k, v in dict(
    max_messages=os.environ.get('PUBSUB_MAX_MESSAGES'),
    max_bytes=os.environ.get('PUBSUB_MAX_BYTES'),
    max_lease_duration=os.environ.get('PUBSUB_MAX_LEASE_DURATION'),
).items() if v is not None}

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

if python_policy_path is not None:
    python_engine = {
        'type': 'python',
        'path': python_policy_path,
    }
    rpeconfig['policy_engines'].append(python_engine)

rpe = RPE(rpeconfig)

running_config = {
    'policies': rpe.policies(),
    'policy_enforcement': "enabled" if enforce_policy else "disabled",
    'stackdriver_logging': "enabled" if stackdriver_logging else "disabled",
    'enforcement_delay': enforcement_delay,
    'debug_logging': "enabled" if debug_logging else "disabled",
    'python_policy_path': python_policy_path,
    'flow_control_config': flow_control_config,
}
logger(running_config)


def callback(pubsub_message):

    # We use the message ID in all logs we emit
    message_id = pubsub_message.message_id

    # Only one message parser should be able to parse a given message, lets capture which one it is
    parser_match = None

    for parser in message_parsers:

        try:
            if not parser.match(pubsub_message):
                logger.debug({'message_id': message_id, 'message': f'Message not matched by parser {parser.__name__}'})
                continue

            logger.debug({'message_id': message_id, 'message': f'Message matched by parser {parser.__name__}'})

            parsed_message = parser.parse_message(pubsub_message)
            parser_match = parser

            if len(parsed_message.resources) == 0:
                # We did not recognize any assets in this message
                logger.debug({
                    'message_id':
                    message_id, 'message': f'No resources identified in message parsed by {parser.__name__}',
                    'metadata': parsed_message.metadata.dict()
                })

                pubsub_message.ack()
                return
            break

        except Exception as e:
            logger({
                'message_id': message_id,
                'message': f'Exception while parsing message with {parser.__name__}',
                **exc_info(e)
            })

    # If no message parsers were able to parse the message, log and return
    if parser_match is None:
        logger({'message_id': message_id, 'message': 'No parsers recognized the message format, discarding message'})
        pubsub_message.ack()
        return

    for resource in parsed_message.resources:

        try:

            logger.debug({
                'message_id': message_id,
                'message': 'Processing resource',
                'resource_data': resource.to_dict(),
            })

            # Set the resource's credentials before any API calls
            resource_creds = cb.get_credentials(
                **resource.to_dict(),
            )
            resource.client_kwargs = {
                'credentials': resource_creds
            }

            project_logger = None
            if per_project_logging and resource.project_id is not None:
                project_logger = Logger(
                    app_name,
                    True,  # per-project logging is always stackdriver
                    resource.project_id,
                    resource_creds
                )

        except Exception as e:
            logger({
                'message_id': message_id,
                'message': 'Exception while getting credentials for resource',
                'metadata': parsed_message.metadata.dict(),
                'resource_data': resource.to_dict(),
                **exc_info(e),
            })
            pubsub_message.ack()
            continue

        logger.debug({'message_id': message_id, 'message': 'Evaluating resource against policies'})

        try:
            evaluations = rpe.evaluate(resource)
            eval_time = int(time.time())
        except Exception as e:
            logger({
                'message_id': message_id,
                'resource_data': resource.to_dict(),
                'message': 'Exception while evaluating resource',
                'metadata': parsed_message.metadata.dict(),
                **exc_info(e),
            })
            pubsub_message.ack()
            continue

        if len(evaluations) < 1:
            logger.debug({'message_id': message_id, 'message': 'No policies matched resource'})

        # Log the results of evaluations on each policy for this resource
        for evaluation in evaluations:

            # Call hook to allow for customization
            hooks.process_evaluation(evaluation, parsed_message)

            evaluation_log = {
                'compliant': evaluation.compliant,
                'event': 'evaluation',
                'excluded': evaluation.excluded,
                'message_id': message_id,
                'metadata': parsed_message.metadata.dict(),
                'policy_id': evaluation.policy_id,
                'remediable': evaluation.remediable,
                'resource_data': resource.to_dict(),
                'timestamp': eval_time,
            }

            logger(evaluation_log)

            if project_logger is not None:
                project_logger(evaluation_log)

        if enforce_policy and parsed_message.control_data.enforce:

            if enforcement_delay and parsed_message.control_data.delay_enforcement:

                delay_timestamp = parsed_message.metadata.timestamp or message_timestamp
                message_age = int(time.time()) - delay_timestamp

                # If the log is old, subtract that from the enforcement delay
                delay = max(0, enforcement_delay - message_age)
                logger.debug({
                    'message_id': message_id,
                    'message': 'Delaying enforcement by %d seconds, message is already %d seconds old and our'
                               'configured delay is %d seconds' % (delay, message_age, enforcement_delay)
                })
                time.sleep(delay)

            for evaluation in evaluations:

                if not (evaluation.compliant or evaluation.excluded) and evaluation.remediable:
                    logger.debug({'message_id': message_id, 'message': 'Executing remediation'})

                    try:
                        evaluation.remediate()
                        remediation_timestamp = int(time.time())

                        remediation_log = {
                            'event': 'remediation',
                            'message_id': message_id,
                            'metadata': parsed_message.metadata.dict(),
                            'policy_id': evaluation.policy_id,
                            'resource_data': resource.to_dict(),
                            'timestamp': remediation_timestamp,
                        }

                        logger(remediation_log)

                        if project_logger is not None:
                            project_logger(remediation_log)

                    except Exception as e:
                        # Catch any other exceptions so we can acknowledge the message.
                        # Otherwise they start to fill up the buffer of unacknowledged messages
                        logger(dict(
                            message='Execption while attempting to remediate',
                            message_id=message_id,
                            metadata=parsed_message.metadata.dict(),
                            policy_id=evaluation.policy_id,
                            resource_data=resource.to_dict(),
                            **exc_info(e),
                        ))

        else:
            logger.debug({'message_id': message_id, 'message': 'Enforcement is disabled, processing complete'})

    # Finally ack the message after we're done with all of the assets
    pubsub_message.ack()


def exc_info(exception):
    return {
        'event': 'exception',
        'details': str(exception),
        'trace': traceback.format_exc(),
    }


if __name__ == "__main__":

    subscriber = pubsub.SubscriberClient(credentials=app_creds)

    subscription_path = 'projects/{project_id}/subscriptions/{sub}'.format(
        project_id=project_id,
        sub=subscription_name
    )

    flow_control = pubsub.types.FlowControl(
        **flow_control_config
    )

    future = subscriber.subscribe(
        subscription_path,
        callback=callback,
        flow_control=flow_control,
    )

    logger("Listening for pubsub messages on {}...".format(subscription_path))

    try:
        future.result()
    except Exception:
        future.cancel()
        raise
