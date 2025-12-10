from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ArtifactResponse(BaseModel):
    id: str
    kind: str
    url: str
    filename: str | None = None
    owner_user_id: str | None = None
    created_at: datetime
    description: Optional[str] = None
