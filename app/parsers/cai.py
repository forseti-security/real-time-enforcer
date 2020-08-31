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

import json

from pydantic import BaseModel
from pydantic import ValidationError
from rpe.resources.gcp import GoogleAPIResource
from typing import Optional

from .models import EnforcerControlData
from .models import MessageMetadata
from .models import ParsedMessage


class EnforcementMessage(BaseModel):
    ''' The format of the messages this parser will handle '''
    name: str
    asset_type: str
    project_id: Optional[str] = None
    metadata: MessageMetadata
    control_data: EnforcerControlData = EnforcerControlData(delay_enforcement=False)

    class Config:
        extra = 'forbid'


class CaiParser:

    @classmethod
    def match(cls, message):
        try:
            message_data = json.loads(message.data)
        except (json.JSONDecodeError, AttributeError):
            return False

        try:
            EnforcementMessage(**message_data)
            return True
        except ValidationError:
            return False

    @classmethod
    def parse_message(cls, message):

        message_data = json.loads(message.data)
        publish_timestamp = int(message.publish_time.timestamp())

        m = EnforcementMessage(**message_data)

        resource = GoogleAPIResource.from_cai_data(m.name, m.asset_type, project_id=m.project_id)

        return ParsedMessage(
            resources=[resource],
            metadata=m.metadata,
            control_data=m.control_data,
            timestamp=publish_timestamp,
        )
