from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ArtifactResponse(BaseModel):
    id: str
    kind: str
    url: str
    created_at: datetime
    description: Optional[str] = None
