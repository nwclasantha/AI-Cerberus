"""
Enterprise-Level PDF Report Generator for Malware Analysis.

Generates comprehensive, professional PDF reports with:
- Executive summary with threat classification
- Complete file information and cryptographic hashes
- YARA rule matches with severity indicators
- Behavioral analysis indicators
- PE/ELF structure analysis
- Disassembly highlights (suspicious instructions)
- Entropy analysis with visual charts
- String analysis with IOC extraction
- VirusTotal scan results
- ML classification results
- Legitimacy verification status
- Professional formatting with tables and charts

Author: AI-Cerberus
Version: 1.0.0
"""

from __future__ import annotations

import html
import io
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable, ListFlowable, ListItem,
    KeepTogether, Flowable
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.widgets.markers import makeMarker

from ..utils.logger import get_logger
from ..utils.helpers import format_bytes

logger = get_logger("report_generator")


def escape_xml(text: str) -> str:
    """Escape special XML characters for safe PDF rendering."""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=False)


# ============================================================================
# Custom Flowables for Professional Layout
# ============================================================================

class ThreatGauge(Flowable):
    """Custom threat level gauge visualization."""

    def __init__(self, score: float, width: float = 400, height: float = 60):
        Flowable.__init__(self)
        self.score = min(100, max(0, score))
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        """Return the size needed by this Flowable."""
        return (self.width, self.height)

    def draw(self):
        # Background
        self.canv.setFillColor(colors.Color(0.95, 0.95, 0.95))
        self.canv.roundRect(0, 0, self.width, self.height, 5, fill=1, stroke=0)

        # Score bar background (gradient simulation)
        bar_y = 15
        bar_height = 20
        bar_width = self.width - 40
        bar_x = 20

        # Draw gradient segments
        segments = [
            (0, 20, colors.Color(0.2, 0.8, 0.2)),      # Green (0-20)
            (20, 40, colors.Color(0.6, 0.8, 0.2)),    # Yellow-Green (20-40)
            (40, 60, colors.Color(0.9, 0.7, 0.1)),    # Yellow (40-60)
            (60, 80, colors.Color(0.9, 0.4, 0.1)),    # Orange (60-80)
            (80, 100, colors.Color(0.8, 0.1, 0.1)),   # Red (80-100)
        ]

        for start, end, color in segments:
            seg_x = bar_x + (start / 100) * bar_width
            seg_width = ((end - start) / 100) * bar_width
            self.canv.setFillColor(color)
            self.canv.rect(seg_x, bar_y, seg_width, bar_height, fill=1, stroke=0)

        # Draw border around bar
        self.canv.setStrokeColor(colors.Color(0.5, 0.5, 0.5))
        self.canv.setLineWidth(1)
        self.canv.rect(bar_x, bar_y, bar_width, bar_height, fill=0, stroke=1)

        # Score indicator (triangle pointer)
        indicator_x = bar_x + (self.score / 100) * bar_width
        self.canv.setFillColor(colors.black)
        self.canv.setStrokeColor(colors.black)

        # Draw triangle
        path = self.canv.beginPath()
        path.moveTo(indicator_x, bar_y - 5)
        path.lineTo(indicator_x - 6, bar_y - 15)
        path.lineTo(indicator_x + 6, bar_y - 15)
        path.close()
        self.canv.drawPath(path, fill=1, stroke=0)

        # Score text
        self.canv.setFont("Helvetica-Bold", 12)
        score_text = f"{self.score:.0f}/100"
        self.canv.drawCentredString(indicator_x, bar_y + bar_height + 10, score_text)

        # Labels
        self.canv.setFont("Helvetica", 8)
        self.canv.drawString(bar_x, bar_y - 10, "0")
        self.canv.drawRightString(bar_x + bar_width, bar_y - 10, "100")


class SeverityBadge(Flowable):
    """Colored severity badge."""

    COLORS = {
        "critical": colors.Color(0.8, 0.0, 0.0),
        "high": colors.Color(0.9, 0.3, 0.0),
        "medium": colors.Color(0.9, 0.6, 0.0),
        "low": colors.Color(0.2, 0.6, 0.2),
        "info": colors.Color(0.2, 0.4, 0.8),
        "clean": colors.Color(0.0, 0.6, 0.2),
    }

    def __init__(self, severity: str, width: float = 80, height: float = 20):
        Flowable.__init__(self)
        self.severity = severity.lower()
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        """Return the size needed by this Flowable."""
        return (self.width, self.height)

    def draw(self):
        color = self.COLORS.get(self.severity, colors.gray)
        self.canv.setFillColor(color)
        self.canv.roundRect(0, 0, self.width, self.height, 3, fill=1, stroke=0)

        self.canv.setFillColor(colors.white)
        self.canv.setFont("Helvetica-Bold", 10)
        self.canv.drawCentredString(self.width / 2, 5, self.severity.upper())


# ============================================================================
# Main Report Generator Class
# ============================================================================

class EnterpriseReportGenerator:
    """
    Enterprise-grade PDF report generator for malware analysis results.

    Features:
    - Professional layout with company branding
    - Comprehensive threat assessment
    - Detailed technical analysis sections
    - Visual charts and gauges
    - IOC extraction and formatting
    - Cross-referencing between sections
    """

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.report_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    def _setup_custom_styles(self):
        """Setup custom paragraph styles (prefixed to avoid conflicts)."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='MAReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.Color(0.1, 0.2, 0.4),
            spaceAfter=20,
            alignment=TA_CENTER,
        ))

        # Section header style
        self.styles.add(ParagraphStyle(
            name='MASectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.Color(0.15, 0.25, 0.45),
            spaceBefore=20,
            spaceAfter=10,
            borderPadding=5,
        ))

        # Subsection header
        self.styles.add(ParagraphStyle(
            name='MASubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.Color(0.2, 0.3, 0.5),
            spaceBefore=10,
            spaceAfter=5,
        ))

        # Code style for hashes, instructions, etc. (renamed to avoid conflict)
        self.styles.add(ParagraphStyle(
            name='MACode',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=8,
            textColor=colors.Color(0.2, 0.2, 0.2),
            backColor=colors.Color(0.95, 0.95, 0.95),
            borderPadding=5,
        ))

        # Critical finding style
        self.styles.add(ParagraphStyle(
            name='MACritical',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.Color(0.8, 0.0, 0.0),
            fontName='Helvetica-Bold',
        ))

        # Warning style
        self.styles.add(ParagraphStyle(
            name='MAWarning',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.Color(0.8, 0.4, 0.0),
        ))

        # Clean/safe style
        self.styles.add(ParagraphStyle(
            name='MAClean',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.Color(0.0, 0.5, 0.2),
        ))

        # Justified body text
        self.styles.add(ParagraphStyle(
            name='MABodyJustified',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        ))

        # Footer style
        self.styles.add(ParagraphStyle(
            name='MAFooter',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.gray,
            alignment=TA_CENTER,
        ))

    def generate_report(
        self,
        analysis_results: Dict[str, Any],
        output_path: Optional[Path] = None,
        include_disassembly: bool = True,
        include_strings: bool = True,
        max_strings: int = 1000,
        max_disasm_lines: int = 5000,
    ) -> Path:
        """
        Generate comprehensive PDF report from analysis results.

        Args:
            analysis_results: Complete analysis results dictionary
            output_path: Output file path (auto-generated if None)
            include_disassembly: Include disassembly section
            include_strings: Include strings analysis section
            max_strings: Maximum strings to include
            max_disasm_lines: Maximum disassembly lines

        Returns:
            Path to generated PDF report
        """
        # Generate output path if not provided
        if output_path is None:
            filename = analysis_results.get("file_info", {}).get("filename", "unknown")
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
            output_path = Path(f"MalwareAnalysis_Report_{safe_name}_{self.report_id}.pdf")

        output_path = Path(output_path)

        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=60,
            bottomMargin=60,
        )

        # Build story (content flow)
        story = []

        # Add sections
        story.extend(self._create_cover_page(analysis_results))
        story.append(PageBreak())

        story.extend(self._create_executive_summary(analysis_results))
        story.append(PageBreak())

        story.extend(self._create_file_info_section(analysis_results))
        story.extend(self._create_hash_section(analysis_results))

        story.extend(self._create_threat_breakdown_section(analysis_results))

        story.extend(self._create_legitimacy_section(analysis_results))

        story.extend(self._create_yara_section(analysis_results))

        story.extend(self._create_behavioral_section(analysis_results))

        story.extend(self._create_pe_section(analysis_results))

        story.extend(self._create_entropy_section(analysis_results))

        story.extend(self._create_virustotal_section(analysis_results))

        story.extend(self._create_ml_section(analysis_results))

        if include_strings:
            story.extend(self._create_strings_section(analysis_results, max_strings))

        if include_disassembly:
            story.extend(self._create_disassembly_section(analysis_results, max_disasm_lines))

        story.extend(self._create_ioc_section(analysis_results))

        story.extend(self._create_appendix(analysis_results))

        # Build document with custom page numbering
        doc.build(story, onFirstPage=self._add_page_header_footer,
                  onLaterPages=self._add_page_header_footer)

        logger.info(f"Report generated: {output_path}")
        return output_path

    def _add_page_header_footer(self, canvas, doc):
        """Add header and footer to each page."""
        canvas.saveState()

        # Header line
        canvas.setStrokeColor(colors.Color(0.15, 0.25, 0.45))
        canvas.setLineWidth(1)
        canvas.line(50, A4[1] - 40, A4[0] - 50, A4[1] - 40)

        # Header text
        canvas.setFont("Helvetica-Bold", 10)
        canvas.setFillColor(colors.Color(0.15, 0.25, 0.45))
        canvas.drawString(50, A4[1] - 35, "MALWARE ANALYSIS REPORT")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 50, A4[1] - 35, f"Report ID: {self.report_id}")

        # Footer line
        canvas.line(50, 40, A4[0] - 50, 40)

        # Footer text
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.gray)
        canvas.drawString(50, 25, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        canvas.drawCentredString(A4[0] / 2, 25, "CONFIDENTIAL - FOR AUTHORIZED USE ONLY")
        canvas.drawRightString(A4[0] - 50, 25, f"Page {doc.page}")

        canvas.restoreState()

    # ========================================================================
    # Section Generators
    # ========================================================================

    def _create_cover_page(self, results: Dict) -> List:
        """Create cover page with classification and summary."""
        elements = []

        # Title
        elements.append(Spacer(1, 80))
        elements.append(Paragraph("MALWARE ANALYSIS REPORT", self.styles['MAReportTitle']))
        elements.append(Spacer(1, 20))

        # Horizontal rule
        elements.append(HRFlowable(
            width="80%",
            thickness=2,
            color=colors.Color(0.15, 0.25, 0.45),
            spaceAfter=20,
        ))

        # File name
        filename = results.get("file_info", {}).get("filename", "Unknown File")
        elements.append(Paragraph(f"<b>Subject:</b> {filename}", self.styles['Normal']))
        elements.append(Spacer(1, 30))

        # Threat classification
        threat_score = results.get("threat_score", {})
        score = threat_score.get("score", 0)
        classification = results.get("classification", "unknown")

        # Classification badge - using hex color strings directly
        class_colors = {
            "malicious": "#CC0000",
            "suspicious": "#E68000",
            "benign": "#009933",
            "clean": "#009933",
        }
        class_color_hex = class_colors.get(classification.lower(), "#808080")

        # Large classification display
        elements.append(Paragraph(
            f"<font size=14>THREAT CLASSIFICATION:</font>",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Create inline style to avoid style name conflicts
        classification_style = ParagraphStyle(
            'MAClassification',
            parent=self.styles['Normal'],
            alignment=TA_CENTER,
            fontSize=28
        )
        elements.append(Paragraph(
            f"<font size=28 color='{class_color_hex}'><b>{classification.upper()}</b></font>",
            classification_style
        ))
        elements.append(Spacer(1, 20))

        # Threat score gauge
        elements.append(Paragraph("<b>Threat Score:</b>", self.styles['Normal']))
        elements.append(Spacer(1, 5))
        elements.append(ThreatGauge(score, width=450, height=60))
        elements.append(Spacer(1, 30))

        # Quick summary table
        file_info = results.get("file_info", {})
        hashes = results.get("hashes", {})

        sha256 = hashes.get("sha256", "")
        sha256_display = f"{sha256[:32]}..." if sha256 else "N/A"

        summary_data = [
            ["File Size", file_info.get("size_human", "N/A")],
            ["SHA-256", sha256_display],
            ["Analysis Date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
            ["Report ID", self.report_id],
        ]

        summary_table = Table(summary_data, colWidths=[120, 330])
        summary_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.Color(0.3, 0.3, 0.3)),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(summary_table)

        return elements

    def _create_executive_summary(self, results: Dict) -> List:
        """Create executive summary section."""
        elements = []

        elements.append(Paragraph("1. EXECUTIVE SUMMARY", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        # Overall assessment
        threat_score = results.get("threat_score", {})
        score = threat_score.get("score", 0)
        classification = results.get("classification", "unknown")

        # Determine assessment text based on classification
        if classification.lower() in ["malicious", "critical"]:
            assessment = (
                f"The analyzed file has been classified as <b><font color='red'>MALICIOUS</font></b> "
                f"with a threat score of <b>{score:.0f}/100</b>. This file exhibits characteristics "
                "consistent with malware and poses a significant security risk. "
                "Immediate containment and remediation actions are recommended."
            )
            style = 'Critical'
        elif classification.lower() == "suspicious":
            assessment = (
                f"The analyzed file has been classified as <b><font color='orange'>SUSPICIOUS</font></b> "
                f"with a threat score of <b>{score:.0f}/100</b>. This file exhibits some concerning "
                "characteristics that warrant further investigation. Manual review is recommended."
            )
            style = 'Warning'
        else:
            assessment = (
                f"The analyzed file has been classified as <b><font color='green'>CLEAN/BENIGN</font></b> "
                f"with a threat score of <b>{score:.0f}/100</b>. No significant malicious indicators "
                "were detected. The file appears to be safe for normal operation."
            )
            style = 'Clean'

        elements.append(Paragraph(assessment, self.styles['MABodyJustified']))
        elements.append(Spacer(1, 15))

        # Key findings
        elements.append(Paragraph("<b>Key Findings:</b>", self.styles['MASubsectionHeader']))

        findings = []

        # YARA findings
        yara_matches = results.get("yara_matches", [])
        critical_yara = sum(1 for m in yara_matches if m.get("severity") == "critical")
        high_yara = sum(1 for m in yara_matches if m.get("severity") == "high")
        if yara_matches:
            findings.append(
                f"YARA signature matches: {len(yara_matches)} total "
                f"({critical_yara} critical, {high_yara} high severity)"
            )
        else:
            findings.append("No YARA signature matches detected")

        # Behavioral findings
        behavior = results.get("behavior", {})
        indicators = behavior.get("indicators", [])
        if indicators:
            findings.append(f"Behavioral indicators: {len(indicators)} suspicious behaviors identified")

        # VirusTotal
        vt = results.get("virustotal")
        if vt and isinstance(vt, dict):
            detection_count = vt.get("detection_count", 0)
            total = vt.get("total_engines", 0)
            findings.append(f"VirusTotal: {detection_count}/{total} engines flagged this file")

        # ML Classification
        ml = results.get("ml_classification", {})
        if ml.get("prediction"):
            findings.append(
                f"ML Classification: {ml.get('prediction', 'unknown').upper()} "
                f"({ml.get('confidence', 0)*100:.1f}% confidence)"
            )

        # Legitimacy
        legitimacy = results.get("legitimacy", {})
        if legitimacy.get("is_legitimate"):
            findings.append(
                f"Digital Signature: VERIFIED - {legitimacy.get('publisher', 'Unknown publisher')}"
            )
        elif legitimacy.get("has_valid_signature"):
            findings.append("Digital Signature: Present but not cryptographically verified")

        # Create findings list
        for finding in findings:
            elements.append(Paragraph(f"• {finding}", self.styles['Normal']))

        elements.append(Spacer(1, 15))

        # Recommendations
        elements.append(Paragraph("<b>Recommendations:</b>", self.styles['MASubsectionHeader']))

        if classification.lower() in ["malicious", "critical"]:
            recommendations = [
                "Immediately quarantine the file and prevent execution",
                "Isolate affected systems from the network",
                "Conduct full system scan with updated antivirus software",
                "Preserve the file for forensic analysis",
                "Review system logs for signs of compromise",
                "Report incident to security team",
            ]
        elif classification.lower() == "suspicious":
            recommendations = [
                "Quarantine the file pending further analysis",
                "Submit to additional sandboxing analysis",
                "Review file origin and delivery method",
                "Monitor system for unusual activity",
                "Consider blocking similar files at perimeter",
            ]
        else:
            recommendations = [
                "No immediate action required",
                "Continue standard security monitoring",
                "Maintain updated threat signatures",
            ]

        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles['Normal']))

        return elements

    def _create_file_info_section(self, results: Dict) -> List:
        """Create file information section."""
        elements = []

        elements.append(Paragraph("2. FILE INFORMATION", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        file_info = results.get("file_info", {})
        pe_info = results.get("pe_info", {})

        data = [
            ["Property", "Value"],
            ["Filename", file_info.get("filename", "N/A")],
            ["File Size", file_info.get("size_human", "N/A")],
            ["File Type", pe_info.get("file_type", file_info.get("file_type", "N/A"))],
            ["Architecture", results.get("architecture", pe_info.get("architecture", "N/A"))],
            ["Subsystem", pe_info.get("subsystem", "N/A")],
            ["Entry Point", pe_info.get("entry_point", "N/A")],
            ["Image Base", pe_info.get("image_base", "N/A")],
            ["Compile Time", str(pe_info.get("timestamp", "N/A"))],
            ["Is DLL", "Yes" if pe_info.get("is_dll") else "No"],
            ["Is .NET", "Yes" if pe_info.get("is_dotnet") else "No"],
            ["Is Driver", "Yes" if pe_info.get("is_driver") else "No"],
        ]

        table = Table(data, colWidths=[150, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 15))

        return elements

    def _create_hash_section(self, results: Dict) -> List:
        """Create cryptographic hashes section."""
        elements = []

        elements.append(Paragraph("3. CRYPTOGRAPHIC HASHES", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        hashes = results.get("hashes", {})
        pe_info = results.get("pe_info", {})

        data = [
            ["Algorithm", "Hash Value"],
            ["MD5", hashes.get("md5", "N/A")],
            ["SHA-1", hashes.get("sha1", "N/A")],
            ["SHA-256", hashes.get("sha256", "N/A")],
            ["SHA-512", hashes.get("sha512", "N/A")[:64] + "..." if hashes.get("sha512") else "N/A"],
            ["Import Hash", pe_info.get("imphash", "N/A")],
            ["Rich Header Hash", pe_info.get("rich_hash", "N/A") or "N/A"],
            ["SSDEEP", hashes.get("ssdeep", "N/A")],
        ]

        table = Table(data, colWidths=[100, 400])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, -1), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 15))

        return elements

    def _create_threat_breakdown_section(self, results: Dict) -> List:
        """Create threat score breakdown section."""
        elements = []

        elements.append(Paragraph("4. THREAT SCORE BREAKDOWN", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        threat_score = results.get("threat_score", {})
        breakdown = threat_score.get("breakdown", {})

        elements.append(ThreatGauge(threat_score.get("score", 0), width=450, height=60))
        elements.append(Spacer(1, 15))

        # Breakdown table
        data = [["Detection Source", "Score", "Contribution"]]

        total = sum(breakdown.values()) if breakdown else 1
        for source, score_val in sorted(breakdown.items(), key=lambda x: -x[1]):
            pct = (score_val / total * 100) if total > 0 else 0
            data.append([source.replace("_", " ").title(), f"{score_val:.1f}", f"{pct:.1f}%"])

        if len(data) > 1:
            table = Table(data, colWidths=[200, 100, 100])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No detailed breakdown available.", self.styles['Normal']))

        elements.append(Spacer(1, 15))

        return elements

    def _create_legitimacy_section(self, results: Dict) -> List:
        """Create digital signature and legitimacy section."""
        elements = []

        elements.append(Paragraph("5. DIGITAL SIGNATURE & LEGITIMACY", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        legitimacy = results.get("legitimacy", {})
        pe_info = results.get("pe_info", {})

        # Signature status
        if legitimacy.get("signature_verified"):
            status = "✓ VERIFIED (Cryptographically Validated)"
            status_color = "green"
        elif legitimacy.get("has_valid_signature"):
            status = "⚠ SIGNED (Not Cryptographically Verified)"
            status_color = "orange"
        elif pe_info.get("is_signed"):
            status = "⚠ SIGNATURE PRESENT (Validation Failed)"
            status_color = "orange"
        else:
            status = "✗ NO DIGITAL SIGNATURE"
            status_color = "red"

        elements.append(Paragraph(
            f"<b>Signature Status:</b> <font color='{status_color}'>{status}</font>",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Legitimacy details
        data = [
            ["Property", "Value"],
            ["Is Legitimate", "Yes" if legitimacy.get("is_legitimate") else "No"],
            ["Confidence", f"{legitimacy.get('confidence', 0)*100:.1f}%"],
            ["Publisher", legitimacy.get("publisher", "N/A") or "N/A"],
            ["Reason", legitimacy.get("reason", "N/A")],
            ["Signer", pe_info.get("signer", "N/A") or "N/A"],
        ]

        table = Table(data, colWidths=[150, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 15))

        return elements

    def _create_yara_section(self, results: Dict) -> List:
        """Create YARA matches section."""
        elements = []

        elements.append(Paragraph("6. YARA SIGNATURE MATCHES", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        yara_matches = results.get("yara_matches", [])

        if not yara_matches:
            elements.append(Paragraph(
                "<font color='green'>✓ No YARA signature matches detected.</font>",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 15))
            return elements

        # Summary
        critical = sum(1 for m in yara_matches if m.get("severity") == "critical")
        high = sum(1 for m in yara_matches if m.get("severity") == "high")
        medium = sum(1 for m in yara_matches if m.get("severity") == "medium")
        low = sum(1 for m in yara_matches if m.get("severity") == "low")

        elements.append(Paragraph(
            f"<b>Total Matches:</b> {len(yara_matches)} "
            f"(<font color='red'>{critical} critical</font>, "
            f"<font color='orange'>{high} high</font>, "
            f"<font color='#CC9900'>{medium} medium</font>, "
            f"<font color='green'>{low} low</font>)",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Matches table
        data = [["Rule Name", "Category", "Severity", "Description"]]

        severity_colors = {
            "critical": colors.Color(0.8, 0.0, 0.0),
            "high": colors.Color(0.9, 0.4, 0.0),
            "medium": colors.Color(0.8, 0.6, 0.0),
            "low": colors.Color(0.2, 0.6, 0.2),
        }

        for match in sorted(yara_matches, key=lambda x:
                           {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 4)):
            rule = match.get("rule", "N/A")
            category = match.get("category", match.get("tags", ["N/A"])[0] if match.get("tags") else "N/A")
            if isinstance(category, list):
                category = category[0] if category else "N/A"
            severity = match.get("severity", "medium")
            desc = match.get("description", "No description")[:80]

            data.append([rule, category, severity.upper(), desc])

        # Limit to first 50 matches for readability
        if len(data) > 51:
            data = data[:51]
            elements.append(Paragraph(
                f"<i>Showing first 50 of {len(yara_matches)} matches...</i>",
                self.styles['Normal']
            ))

        table = Table(data, colWidths=[120, 80, 70, 230])

        # Build style commands
        style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]

        # Color severity cells
        for i, row in enumerate(data[1:], 1):
            sev = row[2].lower()
            if sev in severity_colors:
                style_commands.append(('TEXTCOLOR', (2, i), (2, i), severity_colors[sev]))
                style_commands.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))

        table.setStyle(TableStyle(style_commands))
        elements.append(table)
        elements.append(Spacer(1, 15))

        return elements

    def _create_behavioral_section(self, results: Dict) -> List:
        """Create behavioral analysis section."""
        elements = []

        elements.append(Paragraph("7. BEHAVIORAL ANALYSIS", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        behavior = results.get("behavior", {})
        indicators = behavior.get("indicators", [])
        categories = behavior.get("categories", {})
        risk = behavior.get("risk", {})

        # Risk level
        risk_level = risk.get("level", "unknown")
        risk_score = risk.get("score", 0)

        risk_colors = {
            "critical": "red",
            "high": "orange",
            "medium": "#CC9900",
            "low": "green",
        }

        elements.append(Paragraph(
            f"<b>Risk Level:</b> <font color='{risk_colors.get(risk_level, 'gray')}'>"
            f"{risk_level.upper()}</font> (Score: {risk_score})",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Categories breakdown
        if categories:
            elements.append(Paragraph("<b>Behavior Categories:</b>", self.styles['MASubsectionHeader']))

            data = [["Category", "Count", "Severity"]]
            for cat, info in sorted(categories.items(), key=lambda x: -x[1].get("count", 0)):
                count = info.get("count", 0) if isinstance(info, dict) else info
                sev = info.get("severity", "medium") if isinstance(info, dict) else "medium"
                data.append([cat.replace("_", " ").title(), str(count), sev.upper()])

            if len(data) > 1:
                table = Table(data, colWidths=[200, 80, 80])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 10))

        # Indicators list
        if indicators:
            elements.append(Paragraph("<b>Detected Indicators:</b>", self.styles['MASubsectionHeader']))

            for indicator in indicators[:30]:  # Limit to 30
                if isinstance(indicator, dict):
                    text = indicator.get("description", indicator.get("name", str(indicator)))
                else:
                    text = str(indicator)
                elements.append(Paragraph(f"• {text}", self.styles['Normal']))

            if len(indicators) > 30:
                elements.append(Paragraph(
                    f"<i>...and {len(indicators) - 30} more indicators</i>",
                    self.styles['Normal']
                ))
        else:
            elements.append(Paragraph(
                "<font color='green'>✓ No suspicious behavioral indicators detected.</font>",
                self.styles['Normal']
            ))

        elements.append(Spacer(1, 15))

        return elements

    def _create_pe_section(self, results: Dict) -> List:
        """Create PE structure section."""
        elements = []

        elements.append(Paragraph("8. PE STRUCTURE ANALYSIS", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        sections = results.get("sections", [])
        imports = results.get("imports", [])
        pe_info = results.get("pe_info", {})

        # Anomalies
        anomalies = pe_info.get("anomalies", [])
        if anomalies:
            elements.append(Paragraph("<b>Detected Anomalies:</b>", self.styles['MASubsectionHeader']))
            for anomaly in anomalies[:10]:
                elements.append(Paragraph(f"<font color='red'>⚠ {anomaly}</font>", self.styles['Normal']))
            elements.append(Spacer(1, 10))

        # Sections table
        if sections:
            elements.append(Paragraph("<b>PE Sections:</b>", self.styles['MASubsectionHeader']))

            data = [["Name", "Virtual Size", "Raw Size", "Entropy", "Flags"]]
            for section in sections:
                name = section.get("name", "N/A")
                v_size = section.get("virtual_size", 0)
                r_size = section.get("raw_size", 0)
                entropy = section.get("entropy", 0)

                flags = []
                if section.get("is_executable"):
                    flags.append("EXEC")
                if section.get("is_writable"):
                    flags.append("WRITE")
                if section.get("is_suspicious"):
                    flags.append("⚠SUSPICIOUS")

                # Color entropy based on value
                entropy_str = f"{entropy:.2f}"

                data.append([name, str(v_size), str(r_size), entropy_str, " ".join(flags)])

            table = Table(data, colWidths=[80, 80, 80, 60, 200])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (1, 0), (3, -1), 'RIGHT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 10))

        # Import summary
        if imports:
            elements.append(Paragraph("<b>Import Summary:</b>", self.styles['MASubsectionHeader']))

            total_funcs = sum(len(imp.get("functions", [])) for imp in imports)
            elements.append(Paragraph(
                f"Total DLLs: {len(imports)}, Total Functions: {total_funcs}",
                self.styles['Normal']
            ))

            # Show top imports
            data = [["DLL", "Function Count"]]
            for imp in sorted(imports, key=lambda x: -len(x.get("functions", [])))[:15]:
                dll = imp.get("dll", "N/A")
                count = len(imp.get("functions", []))
                data.append([dll, str(count)])

            table = Table(data, colWidths=[300, 100])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            elements.append(table)

        elements.append(Spacer(1, 15))

        return elements

    def _create_entropy_section(self, results: Dict) -> List:
        """Create entropy analysis section."""
        elements = []

        elements.append(Paragraph("9. ENTROPY ANALYSIS", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        entropy = results.get("entropy", {})

        overall = entropy.get("overall_entropy", entropy.get("overall", 0))
        assessment = entropy.get("assessment", "normal")

        # Assessment color
        assessment_colors = {
            "encrypted": "red",
            "packed": "orange",
            "compressed": "#CC9900",
            "normal": "green",
        }

        elements.append(Paragraph(
            f"<b>Overall Entropy:</b> {overall:.4f} bits/byte",
            self.styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Assessment:</b> <font color='{assessment_colors.get(assessment, 'gray')}'>"
            f"{assessment.upper()}</font>",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Interpretation
        if assessment == "encrypted":
            interp = "High entropy suggests the file may be encrypted or heavily obfuscated. This is common in packed malware."
        elif assessment == "packed":
            interp = "Elevated entropy indicates the file is likely packed or compressed. This can be used to evade detection."
        elif assessment == "compressed":
            interp = "Moderate-high entropy suggests some compression or encoding. This is common in legitimate executables."
        else:
            interp = "Normal entropy levels consistent with standard executable code and data."

        elements.append(Paragraph(f"<i>{interp}</i>", self.styles['Normal']))
        elements.append(Spacer(1, 15))

        return elements

    def _create_virustotal_section(self, results: Dict) -> List:
        """Create VirusTotal results section."""
        elements = []

        elements.append(Paragraph("10. VIRUSTOTAL SCAN RESULTS", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        vt = results.get("virustotal")

        if not vt or not isinstance(vt, dict):
            elements.append(Paragraph(
                "<i>VirusTotal results not available. File may not be in VT database or API not configured.</i>",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 15))
            return elements

        detection_count = vt.get("detection_count", 0)
        total_engines = vt.get("total_engines", 0)
        detection_ratio = detection_count / total_engines if total_engines > 0 else 0

        # Detection ratio color
        if detection_ratio >= 0.5:
            color = "red"
            assessment = "HIGH RISK"
        elif detection_ratio >= 0.3:
            color = "orange"
            assessment = "MEDIUM RISK"
        elif detection_ratio >= 0.1:
            color = "#CC9900"
            assessment = "LOW RISK"
        elif detection_count > 0:
            color = "#999900"
            assessment = "MINIMAL DETECTIONS"
        else:
            color = "green"
            assessment = "CLEAN"

        elements.append(Paragraph(
            f"<b>Detection Ratio:</b> <font color='{color}' size=14><b>{detection_count}/{total_engines}</b></font> "
            f"({detection_ratio*100:.1f}%)",
            self.styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Assessment:</b> <font color='{color}'>{assessment}</font>",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Detections list - handle both dict and list formats
        detections = vt.get("detections", vt.get("scans", {}))
        if detections:
            elements.append(Paragraph("<b>Engine Detections:</b>", self.styles['MASubsectionHeader']))

            data = [["Engine", "Result"]]
            detection_count_shown = 0
            total_detections = 0

            # Handle dictionary format: {engine_name: {detected: bool, result: str}}
            if isinstance(detections, dict):
                total_detections = len(detections)
                for engine, info in list(detections.items())[:30]:
                    if isinstance(info, dict):
                        if info.get("detected") or info.get("result"):
                            result = info.get("result", "Detected")
                            if result:
                                data.append([str(engine), str(result)[:50]])
                                detection_count_shown += 1
                    elif isinstance(info, str):
                        if info:
                            data.append([str(engine), str(info)[:50]])
                            detection_count_shown += 1

            # Handle list format: [{engine: str, result: str}] or [str]
            elif isinstance(detections, list):
                total_detections = len(detections)
                for det in detections[:30]:
                    if isinstance(det, dict):
                        engine = det.get("engine", det.get("name", "Unknown"))
                        result = det.get("result", det.get("detection", "Detected"))
                        if result:
                            data.append([str(engine), str(result)[:50]])
                            detection_count_shown += 1
                    elif isinstance(det, str):
                        parts = det.split(": ", 1)
                        engine = parts[0] if len(parts) > 1 else "Unknown"
                        result = parts[1] if len(parts) > 1 else det
                        data.append([str(engine), str(result)[:50]])
                        detection_count_shown += 1

            if len(data) > 1:
                table = Table(data, colWidths=[150, 350])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('TEXTCOLOR', (1, 1), (1, -1), colors.Color(0.8, 0.0, 0.0)),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(table)

                if total_detections > 30:
                    elements.append(Paragraph(
                        f"<i>...and {total_detections - 30} more detections</i>",
                        self.styles['Normal']
                    ))

        elements.append(Spacer(1, 15))

        return elements

    def _create_ml_section(self, results: Dict) -> List:
        """Create ML classification section."""
        elements = []

        elements.append(Paragraph("11. MACHINE LEARNING CLASSIFICATION", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        ml = results.get("ml_classification", {})

        if not ml:
            elements.append(Paragraph(
                "<i>ML classification results not available.</i>",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 15))
            return elements

        prediction = ml.get("prediction", "unknown")
        confidence = ml.get("confidence", 0)
        method = ml.get("method", "unknown")

        # Prediction color
        pred_colors = {
            "malicious": "red",
            "suspicious": "orange",
            "benign": "green",
            "clean": "green",
        }

        elements.append(Paragraph(
            f"<b>Prediction:</b> <font color='{pred_colors.get(prediction.lower(), 'gray')}' size=12>"
            f"<b>{prediction.upper()}</b></font>",
            self.styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Confidence:</b> {confidence*100:.1f}%",
            self.styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Method:</b> {method.replace('_', ' ').title()}",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Feature importance (if available)
        features = ml.get("feature_importance", ml.get("features", {}))
        if features and isinstance(features, dict):
            elements.append(Paragraph("<b>Key Features:</b>", self.styles['MASubsectionHeader']))

            data = [["Feature", "Value/Score"]]
            for feat, val in list(features.items())[:15]:
                if isinstance(val, float):
                    val_str = f"{val:.4f}"
                else:
                    val_str = str(val)[:50]
                data.append([feat.replace("_", " ").title(), val_str])

            if len(data) > 1:
                table = Table(data, colWidths=[250, 150])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(table)

        elements.append(Spacer(1, 15))

        return elements

    def _create_strings_section(self, results: Dict, max_strings: int = 500) -> List:
        """Create strings analysis section."""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph("12. STRINGS ANALYSIS", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        strings_data = results.get("strings", {})

        total_strings = strings_data.get("total_count", strings_data.get("total", 0))
        strings_list = strings_data.get("strings", strings_data.get("interesting", []))

        elements.append(Paragraph(
            f"<b>Total Strings Extracted:</b> {total_strings}",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Categorize strings
        urls = []
        ips = []
        paths = []
        suspicious = []
        registry = []

        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        path_pattern = re.compile(r'[A-Z]:\\[^\s<>"{}|\\^`\[\]]*', re.IGNORECASE)
        registry_pattern = re.compile(r'(HKEY_|SOFTWARE\\|CurrentVersion)', re.IGNORECASE)

        for s in strings_list[:max_strings]:
            if isinstance(s, dict):
                string = s.get("value", s.get("string", str(s)))
            else:
                string = str(s)

            if url_pattern.search(string):
                urls.append(string)
            elif ip_pattern.search(string):
                ips.append(string)
            elif path_pattern.search(string):
                paths.append(string)
            elif registry_pattern.search(string):
                registry.append(string)

        # URLs
        if urls:
            elements.append(Paragraph("<b>URLs Found:</b>", self.styles['MASubsectionHeader']))
            for url in urls[:20]:
                elements.append(Paragraph(
                    f"<font name='Courier' size=8>{escape_xml(url[:100])}</font>",
                    self.styles['Normal']
                ))
            if len(urls) > 20:
                elements.append(Paragraph(f"<i>...and {len(urls) - 20} more URLs</i>", self.styles['Normal']))
            elements.append(Spacer(1, 10))

        # IP Addresses
        if ips:
            elements.append(Paragraph("<b>IP Addresses Found:</b>", self.styles['MASubsectionHeader']))
            for ip in set(ips[:20]):
                elements.append(Paragraph(
                    f"<font name='Courier' size=8>{escape_xml(ip)}</font>",
                    self.styles['Normal']
                ))
            elements.append(Spacer(1, 10))

        # File Paths
        if paths:
            elements.append(Paragraph("<b>File Paths Found:</b>", self.styles['MASubsectionHeader']))
            for path in paths[:15]:
                elements.append(Paragraph(
                    f"<font name='Courier' size=8>{escape_xml(path[:80])}</font>",
                    self.styles['Normal']
                ))
            if len(paths) > 15:
                elements.append(Paragraph(f"<i>...and {len(paths) - 15} more paths</i>", self.styles['Normal']))
            elements.append(Spacer(1, 10))

        # Registry Keys
        if registry:
            elements.append(Paragraph("<b>Registry References:</b>", self.styles['MASubsectionHeader']))
            for reg in registry[:15]:
                elements.append(Paragraph(
                    f"<font name='Courier' size=8>{escape_xml(reg[:80])}</font>",
                    self.styles['Normal']
                ))
            elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 15))

        return elements

    def _create_disassembly_section(self, results: Dict, max_lines: int = 1000) -> List:
        """Create comprehensive disassembly section with full code analysis."""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph("13. DISASSEMBLY ANALYSIS", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        disassembly = results.get("disassembly", [])

        if not disassembly:
            elements.append(Paragraph(
                "<i>Disassembly data not available.</i>",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 15))
            return elements

        elements.append(Paragraph(
            f"<b>Total Instructions Analyzed:</b> {len(disassembly):,}",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Suspicious API patterns for malware detection
        suspicious_api_patterns = [
            "LoadLibrary", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
            "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection", "NtWriteVirtualMemory", "CreateProcess",
            "ShellExecute", "WinExec", "CreateThread", "NtCreateThreadEx",
            "ResumeThread", "SetThreadContext", "QueueUserAPC", "NtQueueApcThread",
            "ReadProcessMemory", "OpenProcess", "VirtualAllocEx", "HeapCreate",
            "InternetOpen", "URLDownload", "HttpSendRequest", "WSAStartup",
            "connect", "send", "recv", "socket", "RegSetValue", "RegCreateKey",
            "CreateFile", "WriteFile", "DeleteFile", "MoveFile", "CopyFile",
            "GetAsyncKeyState", "SetWindowsHook", "GetClipboardData",
            # Additional malware-related APIs
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
            "RtlDecompressBuffer", "RtlCompressBuffer",
            "SetFileAttributes", "SetFileTime", "FindFirstFile", "FindNextFile",
            "EnumProcesses", "EnumProcessModules", "CreateToolhelp32Snapshot",
            "Process32First", "Process32Next", "Thread32First", "Thread32Next",
            "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
            "GetSystemDirectory", "GetWindowsDirectory", "GetTempPath",
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtReadVirtualMemory",
        ]

        # Suspicious instruction patterns
        suspicious_mnemonics = ["syscall", "sysenter", "int 0x80", "int 0x2e"]

        # Anti-debug/analysis patterns in code
        anti_analysis_patterns = ["cpuid", "rdtsc", "in al", "out al", "vmcall", "vmmcall"]

        # Collect suspicious instructions
        suspicious_instrs = []
        call_instrs = []
        jump_instrs = []

        def format_addr(addr):
            """Format address - handle both int and string formats."""
            if isinstance(addr, int):
                return f"0x{addr:08X}"
            elif isinstance(addr, str):
                # Already formatted or needs formatting
                if addr.startswith("0x") or addr.startswith("0X"):
                    return addr
                try:
                    return f"0x{int(addr, 16):08X}"
                except (ValueError, TypeError):
                    return str(addr)
            return str(addr)

        for instr in disassembly[:max_lines]:
            if isinstance(instr, dict):
                mnemonic = instr.get("mnemonic", "")
                op_str = instr.get("op_str", "")
                addr = instr.get("address", 0)
                bytes_hex = instr.get("bytes_hex", instr.get("bytes", ""))
                full_instr = f"{mnemonic} {op_str}"

                # Check for suspicious API calls
                for pattern in suspicious_api_patterns:
                    if pattern.lower() in full_instr.lower():
                        suspicious_instrs.append({
                            "address": addr,
                            "instruction": full_instr,
                            "bytes": bytes_hex,
                            "reason": f"API: {pattern}",
                            "severity": "high"
                        })
                        break

                # Check for suspicious mnemonics
                for susp_mnem in suspicious_mnemonics:
                    if susp_mnem in full_instr.lower():
                        suspicious_instrs.append({
                            "address": addr,
                            "instruction": full_instr,
                            "bytes": bytes_hex,
                            "reason": f"Syscall: {susp_mnem}",
                            "severity": "critical"
                        })
                        break

                # Check for anti-analysis techniques
                for anti_pattern in anti_analysis_patterns:
                    if anti_pattern in mnemonic.lower():
                        suspicious_instrs.append({
                            "address": addr,
                            "instruction": full_instr,
                            "bytes": bytes_hex,
                            "reason": f"Anti-analysis: {anti_pattern}",
                            "severity": "medium"
                        })
                        break

                # Collect call instructions for call graph analysis
                if mnemonic.lower() == "call":
                    call_instrs.append({
                        "address": addr,
                        "target": op_str,
                        "bytes": bytes_hex
                    })

                # Collect jump instructions
                if mnemonic.lower().startswith("j") and mnemonic.lower() != "jmp":
                    jump_instrs.append({
                        "address": addr,
                        "mnemonic": mnemonic,
                        "target": op_str
                    })

        # Show suspicious instructions first if any found
        if suspicious_instrs:
            elements.append(Paragraph(
                f"<b>⚠ Suspicious Instructions Detected:</b> <font color='red'>{len(suspicious_instrs)}</font>",
                self.styles['MASubsectionHeader']
            ))

            elements.append(Paragraph(
                "The following instructions indicate potentially malicious behavior:",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 5))

            susp_data = [["Address", "Bytes", "Instruction", "Reason"]]
            for susp in suspicious_instrs[:100]:  # Show up to 100 suspicious
                susp_data.append([
                    format_addr(susp['address']),
                    str(susp.get('bytes', ''))[:16],
                    susp['instruction'][:35],
                    susp['reason']
                ])

            if len(susp_data) > 1:
                susp_table = Table(susp_data, colWidths=[80, 80, 170, 150])
                susp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.8, 0.1, 0.1)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.Color(1, 0.95, 0.95), colors.Color(1, 0.9, 0.9)]),
                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ]))
                elements.append(susp_table)

                if len(suspicious_instrs) > 100:
                    elements.append(Paragraph(
                        f"<i>...showing 100 of {len(suspicious_instrs)} suspicious instructions</i>",
                        self.styles['Normal']
                    ))
                elements.append(Spacer(1, 15))

        # Show call instructions summary
        if call_instrs:
            elements.append(Paragraph(
                f"<b>Call Instructions Summary:</b> {len(call_instrs)} calls found",
                self.styles['MASubsectionHeader']
            ))

            call_data = [["Address", "Target"]]
            for call in call_instrs[:50]:
                call_data.append([
                    format_addr(call['address']),
                    str(call['target'])[:50]
                ])

            if len(call_data) > 1:
                call_table = Table(call_data, colWidths=[100, 380])
                call_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.2, 0.4, 0.6)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.97, 1)]),
                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ]))
                elements.append(call_table)

                if len(call_instrs) > 50:
                    elements.append(Paragraph(
                        f"<i>...showing 50 of {len(call_instrs)} call instructions</i>",
                        self.styles['Normal']
                    ))
                elements.append(Spacer(1, 15))

        # Show entry point code (first 200 instructions)
        elements.append(Paragraph("<b>Entry Point Disassembly (First 200 Instructions):</b>", self.styles['MASubsectionHeader']))
        elements.append(Paragraph(
            "Complete disassembly starting from the executable's entry point:",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 5))

        data = [["Address", "Bytes", "Instruction"]]
        for instr in disassembly[:200]:
            if isinstance(instr, dict):
                addr = instr.get("address", 0)
                mnemonic = instr.get("mnemonic", "")
                op_str = instr.get("op_str", "")
                bytes_hex = instr.get("bytes_hex", instr.get("bytes", ""))
                if isinstance(bytes_hex, (list, bytes)):
                    bytes_hex = " ".join(f"{b:02x}" for b in bytes_hex) if bytes_hex else ""
                data.append([format_addr(addr), str(bytes_hex)[:20], f"{mnemonic} {op_str}"])

        if len(data) > 1:
            table = Table(data, colWidths=[80, 100, 300])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.95, 0.95)]),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ]))
            elements.append(table)

        # Show extended disassembly if available (in chunks)
        if len(disassembly) > 200:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph(
                f"<b>Extended Disassembly (Instructions 201-{min(max_lines, len(disassembly))}):</b>",
                self.styles['MASubsectionHeader']
            ))

            # Show in batches of 400 up to max_lines total
            batch_start = 200
            batch_size = 400
            max_batches = (max_lines - batch_start) // batch_size + 1  # Calculate batches needed

            for batch_num in range(max_batches):
                start_idx = batch_start + (batch_num * batch_size)
                end_idx = min(start_idx + batch_size, len(disassembly), max_lines)

                if start_idx >= len(disassembly) or start_idx >= max_lines:
                    break

                ext_data = [["Address", "Bytes", "Instruction"]]
                for instr in disassembly[start_idx:end_idx]:
                    if isinstance(instr, dict):
                        addr = instr.get("address", 0)
                        mnemonic = instr.get("mnemonic", "")
                        op_str = instr.get("op_str", "")
                        bytes_hex = instr.get("bytes_hex", instr.get("bytes", ""))
                        if isinstance(bytes_hex, (list, bytes)):
                            bytes_hex = " ".join(f"{b:02x}" for b in bytes_hex) if bytes_hex else ""
                        ext_data.append([format_addr(addr), str(bytes_hex)[:20], f"{mnemonic} {op_str}"])

                if len(ext_data) > 1:
                    ext_table = Table(ext_data, colWidths=[80, 100, 300])
                    ext_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.3, 0.4, 0.5)),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                        ('FONTSIZE', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.85, 0.85, 0.85)),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.97, 0.97, 0.97)]),
                        ('TOPPADDING', (0, 0), (-1, -1), 1),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
                    ]))
                    elements.append(ext_table)

            if len(disassembly) > max_lines:
                elements.append(Paragraph(
                    f"<i>Note: Showing {max_lines:,} of {len(disassembly):,} total instructions. "
                    f"Full disassembly available in raw analysis data.</i>",
                    self.styles['Normal']
                ))

        # Add raw code dump section for comprehensive analysis
        elements.append(PageBreak())
        elements.append(Paragraph("<b>Raw Disassembly Code Dump:</b>", self.styles['MASubsectionHeader']))
        elements.append(Paragraph(
            "Complete text dump of disassembled code for detailed analysis:",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10))

        # Create raw text code dump (up to 500 instructions in compact format)
        code_lines = []
        for instr in disassembly[:min(500, max_lines)]:
            if isinstance(instr, dict):
                addr = instr.get("address", 0)
                mnemonic = instr.get("mnemonic", "")
                op_str = instr.get("op_str", "")
                addr_str = format_addr(addr)
                code_lines.append(f"{addr_str}:  {mnemonic:<8} {op_str}")

        if code_lines:
            # Split into chunks for better PDF rendering
            chunk_size = 50
            for i in range(0, len(code_lines), chunk_size):
                chunk = code_lines[i:i + chunk_size]
                code_text = "<br/>".join(chunk)
                elements.append(Paragraph(code_text, self.styles['MACode']))
                elements.append(Spacer(1, 5))

        elements.append(Spacer(1, 15))

        return elements

    def _create_ioc_section(self, results: Dict) -> List:
        """Create Indicators of Compromise (IOC) summary section."""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph("14. INDICATORS OF COMPROMISE (IOCs)", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        elements.append(Paragraph(
            "The following indicators can be used for threat hunting and detection rule creation:",
            self.styles['MABodyJustified']
        ))
        elements.append(Spacer(1, 10))

        # File hashes
        hashes = results.get("hashes", {})
        elements.append(Paragraph("<b>File Hashes:</b>", self.styles['MASubsectionHeader']))

        data = [
            ["Type", "Value"],
            ["MD5", hashes.get("md5", "N/A")],
            ["SHA-1", hashes.get("sha1", "N/A")],
            ["SHA-256", hashes.get("sha256", "N/A")],
        ]

        table = Table(data, colWidths=[80, 420])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, -1), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10))

        # YARA rule names
        yara_matches = results.get("yara_matches", [])
        if yara_matches:
            elements.append(Paragraph("<b>Matched YARA Rules:</b>", self.styles['MASubsectionHeader']))
            for match in yara_matches[:20]:
                rule = match.get("rule", "Unknown")
                elements.append(Paragraph(f"• {rule}", self.styles['MACode']))
            elements.append(Spacer(1, 10))

        # Network IOCs from strings
        strings_data = results.get("strings", {})
        strings_list = strings_data.get("strings", [])

        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

        urls = set()
        ips = set()

        for s in strings_list[:1000]:
            if isinstance(s, dict):
                string = s.get("value", s.get("string", str(s)))
            else:
                string = str(s)

            for url in url_pattern.findall(string):
                urls.add(url)
            for ip in ip_pattern.findall(string):
                # Filter out common private/local IPs
                if not ip.startswith(("0.", "127.", "192.168.", "10.", "172.16.")):
                    ips.add(ip)

        if urls:
            elements.append(Paragraph("<b>Network URLs:</b>", self.styles['MASubsectionHeader']))
            for url in list(urls)[:10]:
                elements.append(Paragraph(f"• {escape_xml(url[:80])}", self.styles['MACode']))
            elements.append(Spacer(1, 10))

        if ips:
            elements.append(Paragraph("<b>IP Addresses:</b>", self.styles['MASubsectionHeader']))
            for ip in list(ips)[:10]:
                elements.append(Paragraph(f"• {ip}", self.styles['MACode']))
            elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 15))

        return elements

    def _create_appendix(self, results: Dict) -> List:
        """Create appendix with additional technical details."""
        elements = []

        elements.append(PageBreak())
        elements.append(Paragraph("APPENDIX A: ANALYSIS METADATA", self.styles['MASectionHeader']))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.8)))

        # Analysis configuration
        elements.append(Paragraph("<b>Analysis Configuration:</b>", self.styles['MASubsectionHeader']))

        data = [
            ["Parameter", "Value"],
            ["Report Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Report ID", self.report_id],
            ["Analyzer Version", "1.0.0"],
            ["YARA Rules Loaded", str(len(results.get("yara_matches", [])) > 0)],
            ["ML Model", results.get("ml_classification", {}).get("method", "N/A")],
            ["VirusTotal API", "Configured" if results.get("virustotal") else "Not Available"],
        ]

        table = Table(data, colWidths=[200, 300])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.15, 0.25, 0.45)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.8)),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        # Disclaimer
        elements.append(Paragraph("<b>Disclaimer:</b>", self.styles['MASubsectionHeader']))
        elements.append(Paragraph(
            "This report is generated by automated analysis tools and should be used as part of a "
            "comprehensive security assessment. The classification and threat scores are based on "
            "heuristic analysis, signature matching, and machine learning models. False positives "
            "and false negatives may occur. Manual verification by qualified security analysts is "
            "recommended for critical decisions.",
            self.styles['MABodyJustified']
        ))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph(
            "This document contains confidential information and is intended for authorized "
            "personnel only. Unauthorized distribution or use is prohibited.",
            self.styles['MABodyJustified']
        ))

        return elements


# ============================================================================
# Convenience Functions
# ============================================================================

def generate_pdf_report(
    analysis_results: Dict[str, Any],
    output_path: Optional[Path] = None,
    **kwargs
) -> Path:
    """
    Generate enterprise PDF report from analysis results.

    Args:
        analysis_results: Complete analysis results dictionary
        output_path: Output file path (auto-generated if None)
        **kwargs: Additional options passed to generate_report

    Returns:
        Path to generated PDF report
    """
    generator = EnterpriseReportGenerator()
    return generator.generate_report(analysis_results, output_path, **kwargs)


def get_report_generator() -> EnterpriseReportGenerator:
    """Get report generator instance."""
    return EnterpriseReportGenerator()
