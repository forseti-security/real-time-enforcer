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


class Logger:

    ''' Log to console or stackdriver '''

    def __init__(self, log_name, stackdriver=False, project_id=None, credentials=None, debugging=False):

        self.stackdriver = stackdriver
        self.debugging = debugging

        if stackdriver:
            client = google.cloud.logging.Client(project=project_id, credentials=credentials)
            self.sd_logger = client.logger(log_name)

    def __call__(self, data, severity='DEFAULT'):
        if self.stackdriver:
            if isinstance(data, dict):
                self.sd_logger.log_struct(data, severity=severity)
            else:
                self.sd_logger.log_text(data, severity=severity)

        else:
            print(data)

    # Separate function for debug logs
    def debug(self, data):
        if self.debugging:
            self(data, severity='DEBUG')
