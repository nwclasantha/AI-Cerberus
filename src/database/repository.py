"""
Repository pattern implementation for database operations.

Provides a clean abstraction over SQLAlchemy sessions
with transaction management and common query patterns.
"""

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional, Type, TypeVar
from sqlalchemy import create_engine, func, or_, desc, text
from sqlalchemy.orm import Session, sessionmaker

from .models import (
    Base, Sample, Analysis, YaraMatch, StringEntry,
    NetworkIOC, Tag, AnalysisQueue, Setting,
)
from ..utils.exceptions import DatabaseError
from ..utils.logger import get_logger

logger = get_logger("database")

T = TypeVar("T", bound=Base)


class Repository:
    """
    Database repository with transaction management.

    Provides CRUD operations and common queries for all models.
    """

    _instance: Optional["Repository"] = None

    def __new__(cls, db_path: Optional[str] = None) -> "Repository":
        """Singleton pattern for shared database connection."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize repository with database connection.

        Args:
            db_path: Path to SQLite database file
        """
        if self._initialized:
            return

        if db_path is None:
            db_path = str(Path.home() / ".malware_analyzer" / "analysis.db")

        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._db_path = db_path
        self._engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,
            pool_pre_ping=True,
        )

        # Create tables
        Base.metadata.create_all(self._engine)

        # Create session factory
        self._session_factory = sessionmaker(
            bind=self._engine,
            expire_on_commit=False,
        )

        self._initialized = True
        logger.info(f"Database initialized: {db_path}")

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """
        Context manager for database sessions.

        Handles commit/rollback and proper cleanup.

        Yields:
            SQLAlchemy session
        """
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database error: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            session.close()

    # ==========================================================================
    # Sample Operations
    # ==========================================================================

    def get_sample_by_hash(self, sha256: str) -> Optional[Sample]:
        """Get sample by SHA256 hash."""
        with self.session() as session:
            return session.query(Sample).filter(
                Sample.sha256 == sha256
            ).first()

    def get_sample_by_id(self, sample_id: int) -> Optional[Sample]:
        """Get sample by ID."""
        with self.session() as session:
            return session.query(Sample).filter(
                Sample.id == sample_id
            ).first()

    def get_all_samples(self, limit: Optional[int] = None) -> List[Sample]:
        """Get all samples, optionally limited."""
        with self.session() as session:
            query = session.query(Sample).order_by(Sample.last_analyzed.desc())
            if limit:
                query = query.limit(limit)
            return list(query.all())

    def create_sample(self, **kwargs) -> Sample:
        """Create a new sample record."""
        with self.session() as session:
            sample = Sample(**kwargs)
            session.add(sample)
            session.flush()
            return sample

    def update_sample(self, sha256: str, **kwargs) -> Optional[Sample]:
        """Update sample by SHA256."""
        with self.session() as session:
            sample = session.query(Sample).filter(
                Sample.sha256 == sha256
            ).first()
            if sample:
                for key, value in kwargs.items():
                    setattr(sample, key, value)
                sample.last_analyzed = datetime.utcnow()
                session.flush()
            return sample

    def get_or_create_sample(self, sha256: str, **kwargs) -> tuple:
        """
        Get existing sample or create new one.

        Returns:
            Tuple of (sample, created_bool)
        """
        sample = self.get_sample_by_hash(sha256)
        if sample:
            return sample, False
        sample = self.create_sample(sha256=sha256, **kwargs)
        return sample, True

    def search_samples(
        self,
        query: Optional[str] = None,
        classification: Optional[str] = None,
        min_threat_score: Optional[float] = None,
        tags: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Sample]:
        """
        Search samples with filters.

        Args:
            query: Search in filename, hashes
            classification: Filter by classification
            min_threat_score: Minimum threat score
            tags: Filter by tags
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of matching samples
        """
        with self.session() as session:
            q = session.query(Sample)

            if query:
                q = q.filter(or_(
                    Sample.filename.ilike(f"%{query}%"),
                    Sample.sha256.ilike(f"%{query}%"),
                    Sample.md5.ilike(f"%{query}%"),
                ))

            if classification:
                q = q.filter(Sample.classification == classification)

            if min_threat_score is not None:
                q = q.filter(Sample.threat_score >= min_threat_score)

            if tags:
                q = q.join(Sample.tags).filter(Tag.name.in_(tags))

            return q.order_by(desc(Sample.last_analyzed)).offset(offset).limit(limit).all()

    def get_recent_samples(self, limit: int = 20) -> List[Sample]:
        """Get most recently analyzed samples."""
        with self.session() as session:
            return session.query(Sample).order_by(
                desc(Sample.last_analyzed)
            ).limit(limit).all()

    def get_sample_statistics(self) -> dict:
        """Get overall sample statistics."""
        with self.session() as session:
            total = session.query(func.count(Sample.id)).scalar()
            malicious = session.query(func.count(Sample.id)).filter(
                Sample.classification == "malicious"
            ).scalar()
            suspicious = session.query(func.count(Sample.id)).filter(
                Sample.classification == "suspicious"
            ).scalar()
            benign = session.query(func.count(Sample.id)).filter(
                Sample.classification == "benign"
            ).scalar()
            avg_score = session.query(func.avg(Sample.threat_score)).scalar()

            return {
                "total": total or 0,
                "malicious": malicious or 0,
                "suspicious": suspicious or 0,
                "benign": benign or 0,
                "unknown": (total or 0) - (malicious or 0) - (suspicious or 0) - (benign or 0),
                "average_threat_score": round(avg_score or 0, 2),
            }

    # ==========================================================================
    # Analysis Operations
    # ==========================================================================

    def create_analysis(self, sample_id: int, **kwargs) -> Analysis:
        """Create a new analysis record."""
        with self.session() as session:
            analysis = Analysis(sample_id=sample_id, **kwargs)
            session.add(analysis)

            # Update sample analysis count
            sample = session.query(Sample).filter(
                Sample.id == sample_id
            ).first()
            if sample:
                sample.analysis_count = (sample.analysis_count or 0) + 1
                sample.last_analyzed = datetime.utcnow()

            session.flush()
            return analysis

    def get_analyses_for_sample(self, sample_id: int) -> List[Analysis]:
        """Get all analyses for a sample."""
        with self.session() as session:
            return session.query(Analysis).filter(
                Analysis.sample_id == sample_id
            ).order_by(desc(Analysis.timestamp)).all()

    def get_latest_analysis(self, sample_id: int) -> Optional[Analysis]:
        """Get most recent analysis for a sample."""
        with self.session() as session:
            return session.query(Analysis).filter(
                Analysis.sample_id == sample_id
            ).order_by(desc(Analysis.timestamp)).first()

    # ==========================================================================
    # YARA Match Operations
    # ==========================================================================

    def add_yara_matches(
        self,
        analysis_id: int,
        matches: List[dict],
    ) -> List[YaraMatch]:
        """Add YARA matches to an analysis."""
        with self.session() as session:
            yara_matches = []
            for match in matches:
                yara_match = YaraMatch(
                    analysis_id=analysis_id,
                    **match,
                )
                session.add(yara_match)
                yara_matches.append(yara_match)
            session.flush()
            return yara_matches

    def get_yara_statistics(self) -> dict:
        """Get YARA rule match statistics."""
        with self.session() as session:
            total = session.query(func.count(YaraMatch.id)).scalar()
            by_rule = session.query(
                YaraMatch.rule_name,
                func.count(YaraMatch.id).label("count")
            ).group_by(YaraMatch.rule_name).order_by(
                desc("count")
            ).limit(10).all()

            return {
                "total_matches": total or 0,
                "top_rules": [
                    {"rule": rule, "count": count}
                    for rule, count in by_rule
                ],
            }

    # ==========================================================================
    # Tag Operations
    # ==========================================================================

    def get_or_create_tag(self, name: str, **kwargs) -> Tag:
        """Get existing tag or create new one."""
        with self.session() as session:
            tag = session.query(Tag).filter(Tag.name == name).first()
            if tag:
                return tag
            tag = Tag(name=name, **kwargs)
            session.add(tag)
            session.flush()
            return tag

    def add_tag_to_sample(self, sample_id: int, tag_name: str) -> bool:
        """Add tag to sample."""
        with self.session() as session:
            sample = session.query(Sample).filter(
                Sample.id == sample_id
            ).first()
            tag = self.get_or_create_tag(tag_name)

            if sample and tag not in sample.tags:
                sample.tags.append(tag)
                session.flush()
                return True
            return False

    def get_all_tags(self) -> List[Tag]:
        """Get all tags."""
        with self.session() as session:
            return session.query(Tag).order_by(Tag.name).all()

    # ==========================================================================
    # Settings Operations
    # ==========================================================================

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get setting value by key."""
        with self.session() as session:
            setting = session.query(Setting).filter(
                Setting.key == key
            ).first()
            return setting.value if setting else default

    def set_setting(self, key: str, value: str, value_type: str = "string") -> Setting:
        """Set or update a setting."""
        with self.session() as session:
            setting = session.query(Setting).filter(
                Setting.key == key
            ).first()
            if setting:
                setting.value = value
                setting.value_type = value_type
                setting.updated_at = datetime.utcnow()
            else:
                setting = Setting(key=key, value=value, value_type=value_type)
                session.add(setting)
            session.flush()
            return setting

    # ==========================================================================
    # Cleanup Operations
    # ==========================================================================

    def delete_sample(self, sample_id: int) -> bool:
        """Delete sample and all related data."""
        with self.session() as session:
            sample = session.query(Sample).filter(
                Sample.id == sample_id
            ).first()
            if sample:
                session.delete(sample)
                return True
            return False

    def clear_all_samples(self) -> int:
        """
        Clear all samples from database.

        Returns:
            Number of samples deleted
        """
        with self.session() as session:
            count = session.query(Sample).count()
            session.query(Sample).delete()
            return count

    def vacuum_database(self) -> None:
        """Run SQLite VACUUM to reclaim space."""
        with self.session() as session:
            session.execute(text("VACUUM"))


# Global repository instance
_repository: Optional[Repository] = None


def get_repository(db_path: Optional[str] = None) -> Repository:
    """Get global repository instance."""
    global _repository
    if _repository is None:
        _repository = Repository(db_path)
    return _repository


def init_repository(db_path: str) -> Repository:
    """Initialize repository with custom path."""
    global _repository
    _repository = Repository(db_path)
    return _repository
