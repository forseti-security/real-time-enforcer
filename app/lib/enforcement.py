from rpe.policy import Evaluation
from typing import List
from pydantic import BaseModel, Field


class EnforcementDecision(BaseModel):
    evaluation: Evaluation
    enforce: bool = True
    reasons: List = Field([])

    class Config:
        arbitrary_types_allowed = True
