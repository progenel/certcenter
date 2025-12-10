from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import artifacts, auth, certs, envelope, status, users, requests
from app.config import get_settings
from app.db import Base, SessionLocal, engine
from app.models import Role, User, UserRole, Artifact
from app.security import hash_password
from app.ca import load_or_create_ca
from app.crl import build_crl, write_crl


def create_app() -> FastAPI:
    import logging

    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    app = FastAPI(title=settings.app_name, debug=settings.debug)

    static_dir = Path(__file__).resolve().parent.parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

    # Routers
    app.include_router(certs.router)
    app.include_router(status.router)
    app.include_router(envelope.router)
    app.include_router(artifacts.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(requests.router)
    app.mount("/ui", StaticFiles(directory=static_dir, html=True), name="ui")

    @app.middleware("http")
    async def no_cache_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        """Simple liveness probe."""
        return {"status": "ok"}

    @app.on_event("startup")
    def on_startup() -> None:
        import logging
        # Создаем таблицы для MVP (миграции появятся позже)
        Base.metadata.create_all(bind=engine)
        # Готовим каталог для артефактов
        Path(settings.artifacts_path).mkdir(parents=True, exist_ok=True)
        # Создаем/загружаем CA и цепочку/CRL
        base_artifacts = Path(settings.artifacts_path).resolve()
        base_artifacts.mkdir(parents=True, exist_ok=True)
        ca_key_path = base_artifacts / "ca.key"
        ca_cert_path = base_artifacts / "ca.crt"
        ca_key, ca_cert = load_or_create_ca(ca_key_path, ca_cert_path)
        chain_path = base_artifacts / "chain.pem"
        if (not chain_path.exists()) or ("CHAIN_PLACEHOLDER" in chain_path.read_text(encoding="utf-8", errors="ignore")):
            chain_path.write_bytes(ca_cert_path.read_bytes())
        crl_path = base_artifacts / "crl.pem"
        # Всегда записываем актуальную цепочку CA
        chain_path.write_bytes(ca_cert_path.read_bytes())
        if (not crl_path.exists()) or ("CRL_PLACEHOLDER" in crl_path.read_text(encoding="utf-8", errors="ignore")):
            empty_crl = build_crl(ca_key, ca_cert, revoked_serials=[])
            write_crl(empty_crl, crl_path)
        logging.info("init_artifacts chain=%s crl=%s", chain_path, crl_path)
        # Создаем демо-аккаунты admin/admin, officer/officer и user/user
        with SessionLocal() as session:
            for username, full_name, role_name, password in [
                (settings.default_admin_username, "Demo Admin", "admin", settings.default_admin_password),
                (settings.default_officer_username, "Demo Officer", "officer", settings.default_officer_password),
                (settings.default_user_username, "Demo User", "user", settings.default_user_password),
            ]:
                user = session.query(User).filter(User.username == username).first()
                if user is None:
                    user = User(
                        id=username,
                        username=username,
                        full_name=full_name,
                        password_hash=hash_password(password),
                        is_active=True,
                    )
                    session.add(user)
                else:
                    # Обновляем пароль/активность, если пусто
                    if not user.password_hash:
                        user.password_hash = hash_password(password)
                    user.is_active = True
                if session.query(Role).filter(Role.id == role_name).first() is None:
                    session.add(Role(id=role_name, name=role_name, description=f"Demo {role_name} role"))
                if session.query(UserRole).filter(UserRole.user_id == user.id, UserRole.role_id == role_name).first() is None:
                    session.add(UserRole(user_id=user.id, role_id=role_name))
            # Обновляем/создаем артефакты chain/crl с актуальными путями
            chain_art = session.query(Artifact).filter(Artifact.id == "chain").first()
            if chain_art is None:
                session.add(
                    Artifact(
                        id="chain",
                        kind="chain",
                        url=str(chain_path),
                        description="Цепочка CA",
                        owner_user_id=None,
                    )
                )
            else:
                chain_art.url = str(chain_path)
                chain_art.description = "Цепочка CA"
            crl_art = session.query(Artifact).filter(Artifact.id == "crl").first()
            if crl_art is None:
                session.add(
                    Artifact(
                        id="crl",
                        kind="crl",
                        url=str(crl_path),
                        description="CRL",
                        owner_user_id=None,
                    )
                )
            else:
                crl_art.url = str(crl_path)
                crl_art.description = "CRL"
            session.commit()

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
