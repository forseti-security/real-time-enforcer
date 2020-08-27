# Copyright 2020 The Forseti Real Time Enforcer Authors. All rights reserved.
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

class EnforcementDecision:

    def __init__(self, evaluation, trigger):
        self.evaluation = evaluation
        self.trigger = trigger
        self.enforce = True
        self.reasons = []

        self.initial_decision()

    def initial_decision(self):

        # Do we need to
        if self.evaluation.compliant:
            self.cancel('is_compliant')

        # Is it excluded from enforcement
        if self.evaluation.excluded:
            self.cancel('is_excluded')

        # Can we
        if not self.evaluation.remediable:
            self.cancel('is_not_remediable')

        # Does the trigger indicate we shouldn't
        if not self.trigger.control_data.enforce:
            self.cancel('trigger_disabled')

    def cancel(self, reason):
        self.enforce = False
        self.reasons.append(reason)


