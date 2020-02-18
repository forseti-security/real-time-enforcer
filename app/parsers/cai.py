from rpe.resources.gcp import GoogleAPIResource

from .base import ParsedMessage


class CaiParser:

    @classmethod
    def match(cls, message):
        expected_keys = [
            'name',
            'content_type',
            'asset_type',
        ]
        return all(key in message for key in expected_keys)

    @classmethod
    def parse_message(cls, message):

        name = message.get('name')
        asset_type = message.get('asset_type')
        content_type = message.get('content_type')

        metadata = message.get('metadata', {})

        resource = GoogleAPIResource.from_cai_data(name, asset_type, content_type)
        return ParsedMessage([resource], metadata)
