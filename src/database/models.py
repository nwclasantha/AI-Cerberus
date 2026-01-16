"""
SQLAlchemy ORM models for the Malware Analysis Platform.

Defines the database schema for storing analysis results,
samples, and related metadata.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    Text, ForeignKey, Table, JSON, LargeBinary, Index,
    create_engine, event,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship,
    Session,
)


def utcnow() -> datetime:
    """Get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# Many-to-many association table for samples and tags
sample_tags = Table(
    "sample_tags",
    Base.metadata,
    Column("sample_id", Integer, ForeignKey("samples.id"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id"), primary_key=True),
)


class Tag(Base):
    """Tags for categorizing samples."""

    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    color: Mapped[str] = mapped_column(String(7), default="#808080")
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    # Relationships
    samples: Mapped[List["Sample"]] = relationship(
        secondary=sample_tags,
        back_populates="tags",
    )

    def __repr__(self) -> str:
        return f"<Tag(name='{self.name}')>"


class Sample(Base):
    """Represents a malware sample file."""

    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(primary_key=True)

    # File identification
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(String(1000))
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    file_type: Mapped[str] = mapped_column(String(200))

    # Hashes
    md5: Mapped[str] = mapped_column(String(32), index=True)
    sha1: Mapped[str] = mapped_column(String(40), index=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sha512: Mapped[Optional[str]] = mapped_column(String(128))
    ssdeep: Mapped[Optional[str]] = mapped_column(String(200))
    tlsh: Mapped[Optional[str]] = mapped_column(String(100))
    imphash: Mapped[Optional[str]] = mapped_column(String(32))

    # Classification
    classification: Mapped[str] = mapped_column(String(50), default="unknown")
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(50), default="unknown")

    # Metadata
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_analyzed: Mapped[datetime] = mapped_column(default=utcnow)
    analysis_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    # VirusTotal data
    vt_positives: Mapped[Optional[int]] = mapped_column(Integer)
    vt_total: Mapped[Optional[int]] = mapped_column(Integer)
    vt_permalink: Mapped[Optional[str]] = mapped_column(String(500))
    vt_last_checked: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationships
    analyses: Mapped[List["Analysis"]] = relationship(
        back_populates="sample",
        cascade="all, delete-orphan",
    )
    tags: Mapped[List["Tag"]] = relationship(
        secondary=sample_tags,
        back_populates="samples",
    )

    # Indexes
    __table_args__ = (
        Index("idx_sample_classification", "classification"),
        Index("idx_sample_threat_score", "threat_score"),
        Index("idx_sample_first_seen", "first_seen"),
    )

    def __repr__(self) -> str:
        return f"<Sample(sha256='{self.sha256[:16]}...', classification='{self.classification}')>"


class Analysis(Base):
    """Represents a single analysis run on a sample."""

    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id"), nullable=False)

    # Analysis metadata
    timestamp: Mapped[datetime] = mapped_column(default=utcnow)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    analyzer_version: Mapped[str] = mapped_column(String(50))

    # Entropy
    entropy_overall: Mapped[float] = mapped_column(Float, default=0.0)
    entropy_blocks: Mapped[Optional[dict]] = mapped_column(JSON)

    # Binary structure (PE/ELF)
    binary_type: Mapped[str] = mapped_column(String(20))  # pe, elf, macho
    architecture: Mapped[Optional[str]] = mapped_column(String(20))
    entry_point: Mapped[Optional[int]] = mapped_column(Integer)
    image_base: Mapped[Optional[int]] = mapped_column(Integer)
    subsystem: Mapped[Optional[str]] = mapped_column(String(50))
    compile_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Sections/Segments JSON
    sections: Mapped[Optional[dict]] = mapped_column(JSON)
    imports: Mapped[Optional[dict]] = mapped_column(JSON)
    exports: Mapped[Optional[dict]] = mapped_column(JSON)

    # Behavioral indicators
    has_injection: Mapped[bool] = mapped_column(Boolean, default=False)
    has_persistence: Mapped[bool] = mapped_column(Boolean, default=False)
    has_network: Mapped[bool] = mapped_column(Boolean, default=False)
    has_anti_debug: Mapped[bool] = mapped_column(Boolean, default=False)
    has_anti_vm: Mapped[bool] = mapped_column(Boolean, default=False)
    has_crypto: Mapped[bool] = mapped_column(Boolean, default=False)
    has_keylogging: Mapped[bool] = mapped_column(Boolean, default=False)

    # Packer detection
    is_packed: Mapped[bool] = mapped_column(Boolean, default=False)
    packer_name: Mapped[Optional[str]] = mapped_column(String(100))

    # ML classification
    ml_classification: Mapped[Optional[str]] = mapped_column(String(50))
    ml_confidence: Mapped[Optional[float]] = mapped_column(Float)
    ml_features: Mapped[Optional[dict]] = mapped_column(JSON)

    # Full analysis results (compressed JSON)
    full_results: Mapped[Optional[dict]] = mapped_column(JSON)

    # Relationships
    sample: Mapped["Sample"] = relationship(back_populates="analyses")
    yara_matches: Mapped[List["YaraMatch"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
    strings: Mapped[List["StringEntry"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
    network_iocs: Mapped[List["NetworkIOC"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )

    # Indexes
    __table_args__ = (
        Index("idx_analysis_timestamp", "timestamp"),
        Index("idx_analysis_sample", "sample_id"),
    )

    def __repr__(self) -> str:
        return f"<Analysis(id={self.id}, sample_id={self.sample_id}, timestamp='{self.timestamp}')>"


class YaraMatch(Base):
    """YARA rule matches for an analysis."""

    __tablename__ = "yara_matches"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False)

    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_namespace: Mapped[Optional[str]] = mapped_column(String(200))
    rule_file: Mapped[Optional[str]] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    description: Mapped[Optional[str]] = mapped_column(Text)
    matched_strings: Mapped[Optional[dict]] = mapped_column(JSON)
    tags: Mapped[Optional[str]] = mapped_column(String(500))

    # Relationships
    analysis: Mapped["Analysis"] = relationship(back_populates="yara_matches")

    # Indexes
    __table_args__ = (
        Index("idx_yara_rule", "rule_name"),
        Index("idx_yara_analysis", "analysis_id"),
    )

    def __repr__(self) -> str:
        return f"<YaraMatch(rule='{self.rule_name}')>"


class StringEntry(Base):
    """Extracted strings from analysis."""

    __tablename__ = "string_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False)

    offset: Mapped[int] = mapped_column(Integer, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    encoding: Mapped[str] = mapped_column(String(20), default="ascii")
    category: Mapped[str] = mapped_column(String(50), default="generic")
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    analysis: Mapped["Analysis"] = relationship(back_populates="strings")

    # Indexes
    __table_args__ = (
        Index("idx_string_category", "category"),
        Index("idx_string_analysis", "analysis_id"),
    )

    def __repr__(self) -> str:
        truncated = self.value[:30] + "..." if len(self.value) > 30 else self.value
        return f"<StringEntry(value='{truncated}', category='{self.category}')>"


class NetworkIOC(Base):
    """Network Indicators of Compromise."""

    __tablename__ = "network_iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False)

    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)  # ip, domain, url, email
    value: Mapped[str] = mapped_column(String(2000), nullable=False)
    offset: Mapped[Optional[int]] = mapped_column(Integer)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    analysis: Mapped["Analysis"] = relationship(back_populates="network_iocs")

    # Indexes
    __table_args__ = (
        Index("idx_ioc_type", "ioc_type"),
        Index("idx_ioc_value", "value"),
        Index("idx_ioc_analysis", "analysis_id"),
    )

    def __repr__(self) -> str:
        return f"<NetworkIOC(type='{self.ioc_type}', value='{self.value[:50]}')>"


class AnalysisQueue(Base):
    """Queue for pending analysis jobs."""

    __tablename__ = "analysis_queue"

    id: Mapped[int] = mapped_column(primary_key=True)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=5)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    def __repr__(self) -> str:
        return f"<AnalysisQueue(file='{self.file_path}', status='{self.status}')>"


class Setting(Base):
    """Application settings stored in database."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    value: Mapped[str] = mapped_column(Text)
    value_type: Mapped[str] = mapped_column(String(20), default="string")
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)

    def __repr__(self) -> str:
        return f"<Setting(key='{self.key}')>"
