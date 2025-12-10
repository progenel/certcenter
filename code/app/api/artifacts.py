from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import logging

from app.db import get_db
from app.models import Artifact
from app.schemas.artifacts import ArtifactResponse
from app.deps import require_token, check_owner_or_admin
from app.config import get_settings

router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])
settings = get_settings()


@router.get("", response_model=list[ArtifactResponse])
def list_artifacts(user=Depends(require_token), db: Session = Depends(get_db)) -> list[ArtifactResponse]:
    # Пользователь видит свои артефакты + публичные (owner_user_id is None); офицер/админ — все
    if user.username in ("admin", "officer"):
        artifacts = db.query(Artifact).all()
    else:
        artifacts = (
            db.query(Artifact)
            .filter((Artifact.owner_user_id == user.id) | (Artifact.owner_user_id == None))  # noqa: E711
            .all()
        )
    return [
        ArtifactResponse(
            id=a.id,
            kind=a.kind,
            url=a.url,
            created_at=a.created_at,
            description=a.description,
        )
        for a in artifacts
    ]


@router.get("/{artifact_id}", response_model=ArtifactResponse, dependencies=[Depends(require_token)])
def get_artifact(artifact_id: str, db: Session = Depends(get_db)) -> ArtifactResponse:
    a = db.get(Artifact, artifact_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    return ArtifactResponse(
        id=a.id,
        kind=a.kind,
        url=a.url,
        created_at=a.created_at,
        description=a.description,
    )


def _resolve_path(raw_path: str) -> Path:
    base = Path(settings.artifacts_path).resolve()
    path = Path(raw_path).resolve()
    if not str(path).startswith(str(base)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access denied (base={base}, path={path})")
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File not found (path={path})")
    return path


@router.get("/{artifact_id}/download", response_class=FileResponse)
def download_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_token),
) -> FileResponse:
    a = db.get(Artifact, artifact_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    check_owner_or_admin(user, a.owner_user_id)
    try:
        path = _resolve_path(a.url)
    except HTTPException as exc:
        logging.error("artifact_download_failed artifact_id=%s url=%s error=%s", artifact_id, a.url, exc.detail)
        raise
    logging.info("artifact_download artifact_id=%s path=%s", artifact_id, path)
    return FileResponse(
        path,
        filename=path.name,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )
