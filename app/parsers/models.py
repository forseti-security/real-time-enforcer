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


import time
from typing import List
from rpe.resources import Resource
from pydantic import BaseModel, Field


# Parser-supplied metadata is arbitrary, but some fields are required
# currently just `src`
class MessageMetadata(BaseModel):
    src: str

    class Config:
        extra = 'allow'


class EnforcerControlData(BaseModel):
    enforce: bool = True
    delay_enforcement: bool = True

    class Config:
        extra = 'forbid'


class ParsedMessage(BaseModel):
    metadata: MessageMetadata
    resources: List[Resource]
    control_data: EnforcerControlData = EnforcerControlData()
    timestamp: int = Field(default_factory=time.time)

    class Config:
        arbitrary_types_allowed = True
        extra = 'forbid'
