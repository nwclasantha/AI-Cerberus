"""
Fully Automated Learning Engine - NO USER INTERACTION REQUIRED.

This engine automatically learns from scan results without any human feedback.
It uses multiple signals to determine file legitimacy/maliciousness:

1. VirusTotal Consensus - If VT says clean (0/70+ detections), auto-learn legitimate
2. Cryptographic Signatures - Valid Windows signatures = auto-learn legitimate
3. Detection Consensus - If all detection sources agree, auto-learn the result
4. PE Analysis Confidence - High-confidence PE analysis triggers auto-learning
5. Historical Pattern Matching - Similar files to known good/bad = auto-learn

FULLY AUTOMATED - ZERO HUMAN INTERACTION.

Author: AI-Cerberus
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import threading

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger("auto_learning")


@dataclass
class AutoLearnDecision:
    """Decision from auto-learning system."""
    should_learn: bool
    is_legitimate: bool
    confidence: float
    reason: str
    source: str  # What triggered the auto-learn


class AutoLearningDatabase:
    """
    Persistent storage for auto-learned files.

    Stores:
    - File hashes with legitimacy status
    - Publisher reputation (auto-calculated)
    - Pattern signatures for similar file detection
    """

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path.home() / ".malware_analyzer" / "auto_learned.json"
        self._db_path = db_path
        self._lock = threading.Lock()

        # In-memory caches
        self._legitimate_hashes: Set[str] = set()
        self._malicious_hashes: Set[str] = set()
        self._publisher_scores: Dict[str, Dict] = {}
        self._file_patterns: Dict[str, Dict] = {}
        self._learning_history: List[Dict] = []

        self._load()

    def _load(self) -> None:
        """Load database from disk."""
        try:
            if self._db_path.exists():
                with open(self._db_path, 'r') as f:
                    data = json.load(f)
                self._legitimate_hashes = set(data.get('legitimate', []))
                self._malicious_hashes = set(data.get('malicious', []))
                self._publisher_scores = data.get('publishers', {})
                self._file_patterns = data.get('patterns', {})
                self._learning_history = data.get('history', [])[-1000:]  # Keep last 1000

                logger.info(
                    f"Auto-learning DB loaded: {len(self._legitimate_hashes)} legitimate, "
                    f"{len(self._malicious_hashes)} malicious, "
                    f"{len(self._publisher_scores)} publishers"
                )
        except Exception as e:
            logger.warning(f"Failed to load auto-learning DB: {e}")

    def _save(self) -> None:
        """Save database to disk."""
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._db_path, 'w') as f:
                json.dump({
                    'legitimate': list(self._legitimate_hashes),
                    'malicious': list(self._malicious_hashes),
                    'publishers': self._publisher_scores,
                    'patterns': self._file_patterns,
                    'history': self._learning_history[-1000:],
                    'updated': datetime.now(timezone.utc).isoformat(),
                    'version': '1.0.0'
                }, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save auto-learning DB: {e}")

    def learn_legitimate(
        self,
        file_hash: str,
        publisher: str = "",
        reason: str = "",
        confidence: float = 1.0,
        metadata: Optional[Dict] = None
    ) -> None:
        """Auto-learn a file as legitimate."""
        with self._lock:
            file_hash = file_hash.lower()
            self._legitimate_hashes.add(file_hash)
            self._malicious_hashes.discard(file_hash)  # Remove if was malicious

            # Update publisher reputation
            if publisher:
                self._update_publisher_score(publisher, is_legitimate=True, confidence=confidence)

            # Record history
            self._learning_history.append({
                'hash': file_hash[:16],
                'legitimate': True,
                'reason': reason,
                'confidence': confidence,
                'publisher': publisher,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'metadata': metadata or {}
            })

            self._save()
            logger.debug(f"Auto-learned LEGITIMATE: {file_hash[:16]}... ({reason})")

    def learn_malicious(
        self,
        file_hash: str,
        publisher: str = "",
        reason: str = "",
        confidence: float = 1.0,
        metadata: Optional[Dict] = None
    ) -> None:
        """Auto-learn a file as malicious."""
        with self._lock:
            file_hash = file_hash.lower()
            self._malicious_hashes.add(file_hash)
            self._legitimate_hashes.discard(file_hash)  # Remove if was legitimate

            # Update publisher reputation (negative)
            if publisher:
                self._update_publisher_score(publisher, is_legitimate=False, confidence=confidence)

            # Record history
            self._learning_history.append({
                'hash': file_hash[:16],
                'legitimate': False,
                'reason': reason,
                'confidence': confidence,
                'publisher': publisher,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'metadata': metadata or {}
            })

            self._save()
            logger.debug(f"Auto-learned MALICIOUS: {file_hash[:16]}... ({reason})")

    def _update_publisher_score(self, publisher: str, is_legitimate: bool, confidence: float) -> None:
        """Update publisher reputation score."""
        pub_lower = publisher.lower()
        if pub_lower not in self._publisher_scores:
            self._publisher_scores[pub_lower] = {
                'legitimate_count': 0,
                'malicious_count': 0,
                'total_confidence': 0.0,
                'first_seen': datetime.now(timezone.utc).isoformat()
            }

        if is_legitimate:
            self._publisher_scores[pub_lower]['legitimate_count'] += 1
        else:
            self._publisher_scores[pub_lower]['malicious_count'] += 1

        self._publisher_scores[pub_lower]['total_confidence'] += confidence
        self._publisher_scores[pub_lower]['last_seen'] = datetime.now(timezone.utc).isoformat()

    def check_hash(self, file_hash: str) -> Tuple[bool, Optional[bool], float]:
        """
        Check if hash is known.

        Returns:
            (is_known, is_legitimate, confidence)
        """
        file_hash = file_hash.lower()
        if file_hash in self._legitimate_hashes:
            return True, True, 0.95
        if file_hash in self._malicious_hashes:
            return True, False, 0.95
        return False, None, 0.0

    def get_publisher_reputation(self, publisher: str) -> Tuple[float, int, int]:
        """
        Get publisher reputation.

        Returns:
            (reputation_score, legitimate_count, malicious_count)
        """
        if not publisher:
            return 0.5, 0, 0

        pub_data = self._publisher_scores.get(publisher.lower())
        if not pub_data:
            return 0.5, 0, 0

        legit = pub_data['legitimate_count']
        mal = pub_data['malicious_count']
        total = legit + mal

        if total == 0:
            return 0.5, 0, 0

        # Bayesian reputation with prior
        reputation = (legit + 2) / (total + 4)  # Prior of 0.5
        return reputation, legit, mal

    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics."""
        return {
            'total_legitimate': len(self._legitimate_hashes),
            'total_malicious': len(self._malicious_hashes),
            'total_learned': len(self._legitimate_hashes) + len(self._malicious_hashes),
            'publishers_tracked': len(self._publisher_scores),
            'recent_learns': len(self._learning_history),
        }


class AutoLearningEngine:
    """
    Fully Automated Learning Engine.

    Automatically learns from scan results WITHOUT any user interaction.
    Uses multiple signals to determine legitimacy.
    """

    # Thresholds for auto-learning
    VT_CLEAN_THRESHOLD = 3  # Max VT detections to consider "clean"
    VT_MALICIOUS_THRESHOLD = 5  # Min VT detections to auto-learn as malicious
    VT_MIN_ENGINES = 20  # Minimum VT engines for reliable result

    CONSENSUS_THRESHOLD = 0.8  # 80% of sources must agree
    HIGH_CONFIDENCE_THRESHOLD = 0.85  # High confidence for auto-learning

    PE_LEGITIMACY_THRESHOLD = 0.75  # PE analysis score for legitimate

    def __init__(self):
        self._db = AutoLearningDatabase()
        self._signature_verifier = None  # Lazy load
        self._pe_analyzer = None  # Lazy load

    def _get_signature_verifier(self):
        """Lazy load signature verifier."""
        if self._signature_verifier is None:
            try:
                from .false_positive_prevention import CryptographicSignatureVerifier
                self._signature_verifier = CryptographicSignatureVerifier()
            except ImportError:
                pass
        return self._signature_verifier

    def _get_pe_analyzer(self):
        """Lazy load PE analyzer."""
        if self._pe_analyzer is None:
            try:
                from .false_positive_prevention import DynamicPEAnalyzer
                self._pe_analyzer = DynamicPEAnalyzer()
            except ImportError:
                pass
        return self._pe_analyzer

    def process_scan_result(
        self,
        file_path: Path,
        file_hash: str,
        data: bytes,
        scan_result: Dict[str, Any]
    ) -> AutoLearnDecision:
        """
        Process a scan result and auto-learn if confidence is high enough.

        This is called AUTOMATICALLY after every scan - no user interaction.

        Args:
            file_path: Path to scanned file
            file_hash: SHA256 hash of file
            data: File contents
            scan_result: Result from combined analysis engine

        Returns:
            AutoLearnDecision with learning decision
        """
        # Check if already known
        is_known, known_legitimate, known_confidence = self._db.check_hash(file_hash)
        if is_known:
            return AutoLearnDecision(
                should_learn=False,
                is_legitimate=known_legitimate,
                confidence=known_confidence,
                reason="Already known",
                source="database"
            )

        # Try each auto-learning method
        decision = None

        # 1. VirusTotal-based auto-learning (highest priority)
        decision = self._check_virustotal_learning(scan_result, file_hash)
        if decision and decision.should_learn:
            self._apply_learning(decision, file_hash, scan_result)
            return decision

        # 2. Cryptographic signature-based auto-learning
        decision = self._check_signature_learning(file_path, file_hash)
        if decision and decision.should_learn:
            self._apply_learning(decision, file_hash, scan_result)
            return decision

        # 3. Consensus-based auto-learning
        decision = self._check_consensus_learning(scan_result, file_hash)
        if decision and decision.should_learn:
            self._apply_learning(decision, file_hash, scan_result)
            return decision

        # 4. PE analysis-based auto-learning (for clean files)
        decision = self._check_pe_analysis_learning(file_path, data, scan_result, file_hash)
        if decision and decision.should_learn:
            self._apply_learning(decision, file_hash, scan_result)
            return decision

        # 5. High confidence detection auto-learning
        decision = self._check_high_confidence_learning(scan_result, file_hash)
        if decision and decision.should_learn:
            self._apply_learning(decision, file_hash, scan_result)
            return decision

        # No auto-learning triggered
        return AutoLearnDecision(
            should_learn=False,
            is_legitimate=not scan_result.get('is_malicious', False),
            confidence=scan_result.get('confidence', 0.5),
            reason="Confidence too low for auto-learning",
            source="none"
        )

    def _check_virustotal_learning(
        self,
        scan_result: Dict[str, Any],
        file_hash: str
    ) -> Optional[AutoLearnDecision]:
        """
        Auto-learn based on VirusTotal results.

        - 0-3 detections out of 20+ engines = LEGITIMATE
        - 5+ detections = MALICIOUS
        """
        vt_positives = scan_result.get('vt_positives', 0)
        vt_total = scan_result.get('vt_total', 0)

        if vt_total < self.VT_MIN_ENGINES:
            return None  # Not enough VT data

        # Clean file - VT says clean
        if vt_positives <= self.VT_CLEAN_THRESHOLD:
            confidence = 1.0 - (vt_positives / vt_total)
            return AutoLearnDecision(
                should_learn=True,
                is_legitimate=True,
                confidence=confidence,
                reason=f"VirusTotal clean: {vt_positives}/{vt_total} detections",
                source="virustotal_clean"
            )

        # Malicious file - VT detections
        if vt_positives >= self.VT_MALICIOUS_THRESHOLD:
            confidence = min(0.99, vt_positives / vt_total + 0.3)
            return AutoLearnDecision(
                should_learn=True,
                is_legitimate=False,
                confidence=confidence,
                reason=f"VirusTotal detected: {vt_positives}/{vt_total} detections",
                source="virustotal_malicious"
            )

        return None  # Ambiguous result

    def _check_signature_learning(
        self,
        file_path: Path,
        file_hash: str
    ) -> Optional[AutoLearnDecision]:
        """
        Auto-learn based on cryptographic signature verification.

        Files with valid, cryptographically verified signatures from
        known publishers are automatically learned as legitimate.
        """
        verifier = self._get_signature_verifier()
        if verifier is None:
            return None

        try:
            is_signed, is_valid, publisher, details = \
                verifier.verify_signature_cryptographically(file_path)

            if is_signed and is_valid and publisher:
                # Check publisher reputation
                pub_rep, legit_count, mal_count = self._db.get_publisher_reputation(publisher)

                # If publisher has good reputation OR is new (no malicious history)
                if mal_count == 0 or pub_rep > 0.7:
                    confidence = 0.9 if legit_count > 0 else 0.85
                    return AutoLearnDecision(
                        should_learn=True,
                        is_legitimate=True,
                        confidence=confidence,
                        reason=f"Valid cryptographic signature: {publisher}",
                        source="signature_verified"
                    )

                # Publisher has mixed/bad reputation - don't auto-learn
                if mal_count > legit_count:
                    return AutoLearnDecision(
                        should_learn=True,
                        is_legitimate=False,
                        confidence=0.7,
                        reason=f"Signed by untrusted publisher: {publisher}",
                        source="signature_untrusted"
                    )

        except Exception as e:
            logger.debug(f"Signature verification failed: {e}")

        return None

    def _check_consensus_learning(
        self,
        scan_result: Dict[str, Any],
        file_hash: str
    ) -> Optional[AutoLearnDecision]:
        """
        Auto-learn based on detection source consensus.

        If 80%+ of detection sources agree, auto-learn the result.
        """
        sources_agreeing = scan_result.get('sources_agreeing_malicious', 0)
        total_sources = scan_result.get('total_sources', 0)

        if total_sources < 3:
            return None  # Need at least 3 sources for consensus

        consensus_ratio = sources_agreeing / total_sources

        # Strong consensus for malicious
        if consensus_ratio >= self.CONSENSUS_THRESHOLD:
            return AutoLearnDecision(
                should_learn=True,
                is_legitimate=False,
                confidence=consensus_ratio,
                reason=f"Detection consensus: {sources_agreeing}/{total_sources} sources agree malicious",
                source="consensus_malicious"
            )

        # Strong consensus for clean (inverse)
        clean_ratio = 1.0 - consensus_ratio
        if clean_ratio >= self.CONSENSUS_THRESHOLD:
            return AutoLearnDecision(
                should_learn=True,
                is_legitimate=True,
                confidence=clean_ratio * 0.9,  # Slightly lower confidence for clean
                reason=f"Detection consensus: {total_sources - sources_agreeing}/{total_sources} sources agree clean",
                source="consensus_clean"
            )

        return None

    def _check_pe_analysis_learning(
        self,
        file_path: Path,
        data: bytes,
        scan_result: Dict[str, Any],
        file_hash: str
    ) -> Optional[AutoLearnDecision]:
        """
        Auto-learn based on PE analysis for clean-looking files.

        If PE analysis shows high legitimacy AND no malicious indicators,
        auto-learn as legitimate.
        """
        # Only for files not flagged as malicious
        if scan_result.get('is_malicious', False):
            return None

        # Check if PE analysis was done
        pe_score = scan_result.get('pe_legitimacy_score', 0)

        if pe_score == 0:
            # Run PE analysis if not done
            analyzer = self._get_pe_analyzer()
            if analyzer and data:
                try:
                    pe_score, _ = analyzer.analyze(file_path, data)
                except Exception:
                    pass

        if pe_score >= self.PE_LEGITIMACY_THRESHOLD:
            # High PE legitimacy score for clean file
            confidence = pe_score * 0.9
            return AutoLearnDecision(
                should_learn=True,
                is_legitimate=True,
                confidence=confidence,
                reason=f"High PE legitimacy score: {pe_score:.0%}",
                source="pe_analysis"
            )

        return None

    def _check_high_confidence_learning(
        self,
        scan_result: Dict[str, Any],
        file_hash: str
    ) -> Optional[AutoLearnDecision]:
        """
        Auto-learn based on high-confidence scan results.

        If the combined analysis has very high confidence, auto-learn.
        """
        confidence = scan_result.get('confidence', 0)
        is_malicious = scan_result.get('is_malicious', False)
        threat_score = scan_result.get('threat_score', 0)

        if confidence < self.HIGH_CONFIDENCE_THRESHOLD:
            return None

        # High confidence malicious
        if is_malicious and threat_score >= 70:
            return AutoLearnDecision(
                should_learn=True,
                is_legitimate=False,
                confidence=confidence,
                reason=f"High confidence malicious: {threat_score:.0f}/100, {confidence:.0%} conf",
                source="high_confidence_malicious"
            )

        # High confidence clean
        if not is_malicious and threat_score <= 20:
            return AutoLearnDecision(
                should_learn=True,
                is_legitimate=True,
                confidence=confidence * 0.9,
                reason=f"High confidence clean: {threat_score:.0f}/100, {confidence:.0%} conf",
                source="high_confidence_clean"
            )

        return None

    def _apply_learning(
        self,
        decision: AutoLearnDecision,
        file_hash: str,
        scan_result: Dict[str, Any]
    ) -> None:
        """Apply the learning decision to the database."""
        publisher = scan_result.get('publisher_name', '')

        metadata = {
            'threat_score': scan_result.get('threat_score', 0),
            'vt_ratio': scan_result.get('vt_detection_ratio', ''),
            'sources': scan_result.get('total_sources', 0),
        }

        if decision.is_legitimate:
            self._db.learn_legitimate(
                file_hash=file_hash,
                publisher=publisher,
                reason=decision.reason,
                confidence=decision.confidence,
                metadata=metadata
            )
        else:
            self._db.learn_malicious(
                file_hash=file_hash,
                publisher=publisher,
                reason=decision.reason,
                confidence=decision.confidence,
                metadata=metadata
            )

        logger.info(
            f"AUTO-LEARNED: {file_hash[:16]}... as "
            f"{'LEGITIMATE' if decision.is_legitimate else 'MALICIOUS'} "
            f"({decision.source}: {decision.reason})"
        )

    def check_known_file(self, file_hash: str) -> Tuple[bool, Optional[bool], float]:
        """
        Check if a file is already known from auto-learning.

        Returns:
            (is_known, is_legitimate, confidence)
        """
        return self._db.check_hash(file_hash)

    def get_publisher_reputation(self, publisher: str) -> Tuple[float, int, int]:
        """Get auto-learned publisher reputation."""
        return self._db.get_publisher_reputation(publisher)

    def get_stats(self) -> Dict[str, Any]:
        """Get auto-learning statistics."""
        return self._db.get_stats()


# Global instance
_auto_learning_engine: Optional[AutoLearningEngine] = None
_engine_lock = threading.Lock()


def get_auto_learning_engine() -> AutoLearningEngine:
    """Get global auto-learning engine instance."""
    global _auto_learning_engine
    if _auto_learning_engine is None:
        with _engine_lock:
            if _auto_learning_engine is None:
                _auto_learning_engine = AutoLearningEngine()
    return _auto_learning_engine
