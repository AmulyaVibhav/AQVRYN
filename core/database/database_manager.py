"""
Database manager — connection, schema creation, migrations, integrity checks.

Uses SQLAlchemy 2.x with SQLite.
All queries use parameterized statements (via ORM or text() with bindparams).
Never constructs SQL via string concatenation of user input.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from core.database.db_models import Base, DbSchemaVersion
from core.utilities.exceptions import MigrationError
from core.utilities.logging_utils import get_logger

logger = get_logger(__name__)

CURRENT_SCHEMA_VERSION = 1


class DatabaseManager:
    """
    Manages the SQLite database lifecycle.

    Features:
    - WAL mode for better concurrent access
    - Foreign key enforcement
    - Integrity check on open
    - Schema versioning and migrations
    - Transactional session factory
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._engine = None
        self._Session = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Open or create the database.
        Runs integrity check, creates schema, runs pending migrations.
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{self._db_path}"
        self._engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            echo=False,
        )

        # Enable WAL mode and foreign keys for every connection
        @event.listens_for(self._engine, "connect")
        def _on_connect(dbapi_conn, _connection_record):  # type: ignore
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.close()

        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

        # Create tables if they don't exist
        Base.metadata.create_all(self._engine)

        self._run_migrations()
        self._integrity_check()
        logger.info("Database initialized at %s", self._db_path)

    def close(self) -> None:
        if self._engine:
            self._engine.dispose()
            logger.info("Database connection closed.")

    # ------------------------------------------------------------------
    # Session factory
    # ------------------------------------------------------------------

    def session(self) -> Session:
        """Return a new database session."""
        if self._Session is None:
            raise RuntimeError("DatabaseManager not initialized. Call initialize() first.")
        return self._Session()

    # ------------------------------------------------------------------
    # Migrations
    # ------------------------------------------------------------------

    def _run_migrations(self) -> None:
        """Apply any pending schema migrations in order."""
        with self.session() as session:
            # Determine current version
            version_row = session.query(DbSchemaVersion).order_by(
                DbSchemaVersion.version.desc()
            ).first()
            current = version_row.version if version_row else 0

            if current < CURRENT_SCHEMA_VERSION:
                logger.info(
                    "Running migrations from version %d to %d", current, CURRENT_SCHEMA_VERSION
                )
                for version in range(current + 1, CURRENT_SCHEMA_VERSION + 1):
                    self._apply_migration(session, version)
                session.commit()

    def _apply_migration(self, session: Session, version: int) -> None:
        """Apply a specific migration version."""
        migrations = {
            1: self._migration_v1,
        }
        migrator = migrations.get(version)
        if migrator is None:
            raise MigrationError(f"No migration defined for version {version}.")

        try:
            migrator(session)
            session.add(DbSchemaVersion(
                version=version,
                description=f"Migration to version {version}",
            ))
            logger.info("Applied migration v%d", version)
        except Exception as exc:
            raise MigrationError(
                f"Migration v{version} failed.", detail=str(exc)
            ) from exc

    def _migration_v1(self, session: Session) -> None:
        """
        Version 1: Initial schema. Insert default categories.
        All tables already created by Base.metadata.create_all().
        """
        from core.models.vault_models import DEFAULT_CATEGORIES
        from core.database.db_models import DbCategory
        import uuid
        from datetime import datetime, timezone

        for cat_data in DEFAULT_CATEGORIES:
            exists = session.query(DbCategory).filter_by(name=cat_data["name"]).first()
            if not exists:
                session.add(DbCategory(
                    id=str(uuid.uuid4()),
                    name=cat_data["name"],
                    icon=cat_data.get("icon", "folder"),
                    color=cat_data.get("color", "#5865F2"),
                    created_at=datetime.now(timezone.utc),
                ))

    # ------------------------------------------------------------------
    # Integrity check
    # ------------------------------------------------------------------

    def _integrity_check(self) -> None:
        """Run SQLite integrity_check PRAGMA. Raises on failure."""
        with self._engine.connect() as conn:
            result = conn.execute(text("PRAGMA integrity_check")).fetchall()
            if result and result[0][0] != "ok":
                issues = [row[0] for row in result]
                raise MigrationError(
                    "Database integrity check failed.",
                    detail="; ".join(issues),
                )
        logger.debug("Database integrity check passed.")

    def vacuum(self) -> None:
        """Compact the database file."""
        with self._engine.connect() as conn:
            conn.execute(text("VACUUM"))
        logger.info("Database VACUUM completed.")
