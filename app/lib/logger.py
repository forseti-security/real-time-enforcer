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


import google.cloud.logging
from google.protobuf import json_format


class Logger:

    ''' Log to console or stackdriver '''

    def __init__(self, log_name, stackdriver=False, project_id=None, credentials=None, debugging=False):

        self.stackdriver = stackdriver
        self.debugging = debugging

        if stackdriver:
            client = google.cloud.logging.Client(project=project_id, credentials=credentials)
            self.sd_logger = client.logger(log_name)

    def _safe_log_struct(self, data, severity):
        ''' Log struct to stackdriver, but attempt to fix if we encounter a ParseError '''
        try:
            self.sd_logger.log_struct(data, severity=severity)
        except json_format.ParseError:
            # If our logs contain data that the google protobuf parser can't handle, let's try to fix it
            # The stackdriver client uses the protobuf json module, so we'll use that too
            data = json_format.json.loads(json_format.json.dumps(data, default=lambda o: str(o)))
            self.sd_logger.log_struct(data, severity=severity)

    def __call__(self, data, severity='DEFAULT'):
        if self.stackdriver:
            try:

                if isinstance(data, dict):
                    self._safe_log_struct(data, severity)

                else:
                    self.sd_logger.log_text(data, severity=severity)

            except Exception as e:
                ''' If we cant log to stackdriver, log error and message to stdout '''
                print(f'Error writing logs to stackdriver: {str(e)}')
                print(data)

        else:
            print(data)

    # Separate function for debug logs
    def debug(self, data):
        if self.debugging:
            self(data, severity='DEBUG')
