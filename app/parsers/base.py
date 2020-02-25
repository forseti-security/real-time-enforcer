from typing import Any, Dict, List
from rpe.resources import Resource
from pydantic import BaseModel


class EnforcerControlData(BaseModel):
    enforce: bool = True
    delay_enforcement: bool = True

    class Config:
        extra = 'forbid'


class ParsedMessage(BaseModel):
    metadata: Dict[str, Any]
    resources: List[Resource]
    control_data: EnforcerControlData = EnforcerControlData()

    class Config:
        arbitrary_types_allowed = True
