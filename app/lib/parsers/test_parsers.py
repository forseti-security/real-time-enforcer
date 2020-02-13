from .base import ParsedMessage

class NoMatchParser:

    @classmethod
    def match(cls, _):
        return False

    @classmethod
    def parse_message(cls, _):
        pass

class MatchExceptionParser:

    @classmethod
    def match(cls, _):
        assert False

    @classmethod
    def parse_message(cls, _):
        pass
