from pydantic import BaseModel
from pydantic import ValidationError
from rpe.resources.gcp import GoogleAPIResource
from rpe.exceptions import ResourceException

from .base import EnforcerControlData
from .base import ParsedMessage


class MessageMetadata(BaseModel):
    src: str

    class Config:
        extra = 'allow'


class EnforcementMessage(BaseModel):
    name: str
    asset_type: str
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
                resource = GoogleAPIResource.from_cai_data(m.name, m.asset_type, content_type)
                resources.append(resource)
            except ResourceException:
                # Not all asset types support all content types
                pass

        return ParsedMessage(resources=resources, metadata=m.metadata, control_data=m.control_data)
