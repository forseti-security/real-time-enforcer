from typing import List
from rpe.resources import Resource


class ParsedMessage:

    def __init__(self, metadata: dict, resources: List[Resource]):
        self._metadata = metadata
        self._resources = resources

    @property
    def metadata(self):
        return self._metadata

    @property
    def resources(self):
        return self._resources
