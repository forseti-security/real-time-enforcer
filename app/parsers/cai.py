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


from pydantic import BaseModel
from pydantic import ValidationError
from rpe.resources.gcp import GoogleAPIResource
from rpe.exceptions import ResourceException
from typing import Optional

from .base import EnforcerControlData
from .base import ParsedMessage


class MessageMetadata(BaseModel):
    src: str

    class Config:
        extra = 'allow'


class EnforcementMessage(BaseModel):
    name: str
    asset_type: str
    project_id: Optional[str] = None
    metadata: MessageMetadata
    control_data: EnforcerControlData = EnforcerControlData(delay_enforcement=False)

    class Config:
        extra = 'forbid'


class CaiParser:

    content_types = ['resource', 'iam']

    @classmethod
    def match(cls, message):
        try:
            EnforcementMessage(**message)
            return True
        except ValidationError:
            return False

    @classmethod
    def parse_message(cls, message):

        m = EnforcementMessage(**message)

        resources = []
        for content_type in cls.content_types:
            try:
                resource = GoogleAPIResource.from_cai_data(m.name, m.asset_type, content_type, project_id=m.project_id)
                resources.append(resource)
            except ResourceException:
                # Not all asset types support all content types
                pass

        return ParsedMessage(resources=resources, metadata=m.metadata, control_data=m.control_data)
