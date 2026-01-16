"""
Custom VM Sandbox integration.

Provides SSH-based file submission and analysis for custom sandbox VMs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import time
import json
import uuid

from ..utils.config import get_config
from ..utils.logger import get_logger
from ..utils.exceptions import IntegrationError

logger = get_logger("custom_sandbox")


@dataclass
class VMSandboxReport:
    """Custom VM sandbox analysis report."""

    job_id: str
    filename: str = ""
    status: str = "pending"  # pending, running, completed, error

    # Analysis results
    exit_code: int = 0
    execution_time: float = 0.0

    # File operations
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)

    # Network activity
    network_connections: List[Dict] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)

    # Process information
    processes_created: List[Dict] = field(default_factory=list)

    # System changes
    registry_changes: List[str] = field(default_factory=list)

    # Raw output
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> Dict:
        return {
            "job_id": self.job_id,
            "filename": self.filename,
            "status": self.status,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "files_created": len(self.files_created),
            "files_modified": len(self.files_modified),
            "network_connections": len(self.network_connections),
            "processes_created": len(self.processes_created),
        }


class CustomVMSandboxClient:
    """
    Custom VM Sandbox client using SSH/Paramiko.

    Features:
    - SSH connection to sandbox VM
    - File upload via SCP/SFTP
    - Remote execution
    - Result retrieval
    - Process monitoring
    """

    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 22
    ):
        """
        Initialize custom VM sandbox client.

        Args:
            host: VM IP address
            username: SSH username
            password: SSH password
            port: SSH port (default 22)
        """
        config = get_config()

        self._host = host or config.get("integrations.custom_sandbox.host", "")
        self._username = username or config.get("integrations.custom_sandbox.username", "")
        self._password = password or config.get("integrations.custom_sandbox.password", "")
        self._port = port or config.get("integrations.custom_sandbox.port", 22)
        self._enabled = config.get("integrations.custom_sandbox.enabled", False)

        # Remote paths
        self._remote_upload_dir = "/tmp/malware_analysis"
        self._remote_output_dir = "/tmp/malware_results"

        # SSH client
        self._ssh_client = None
        self._sftp_client = None

    @property
    def is_configured(self) -> bool:
        """Check if VM sandbox is configured."""
        return bool(self._host and self._username and self._password) and self._enabled

    def _connect(self):
        """Establish SSH connection to VM."""
        if self._ssh_client is not None:
            return self._ssh_client

        try:
            import paramiko

            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            logger.info(f"Connecting to sandbox VM at {self._host}:{self._port}")

            self._ssh_client.connect(
                hostname=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                timeout=10,
                banner_timeout=10,
            )

            # Create remote directories
            self._execute_command(f"mkdir -p {self._remote_upload_dir}")
            self._execute_command(f"mkdir -p {self._remote_output_dir}")

            logger.info("Successfully connected to sandbox VM")
            return self._ssh_client

        except ImportError:
            raise IntegrationError("paramiko package required for custom VM sandbox")
        except Exception as e:
            logger.error(f"Failed to connect to sandbox VM: {e}")
            raise IntegrationError(f"VM connection failed: {e}")

    def _get_sftp(self):
        """Get SFTP client for file transfers."""
        if self._sftp_client is None:
            ssh = self._connect()
            self._sftp_client = ssh.open_sftp()
        return self._sftp_client

    def _execute_command(self, command: str, timeout: int = 30) -> tuple:
        """
        Execute command on remote VM.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        try:
            ssh = self._connect()
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)

            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')

            return stdout_data, stderr_data, exit_code

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return "", str(e), -1

    def test_connection(self) -> bool:
        """
        Test connection to sandbox VM.

        Returns:
            True if connection successful
        """
        try:
            stdout, stderr, exit_code = self._execute_command("echo 'Connection test'")
            return exit_code == 0 and "Connection test" in stdout
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def submit_file(self, file_path: Path, timeout: int = 300) -> Optional[str]:
        """
        Submit file to sandbox VM for analysis.

        Args:
            file_path: Path to file
            timeout: Analysis timeout in seconds

        Returns:
            Job ID if submitted successfully
        """
        if not self.is_configured:
            logger.warning("Custom VM sandbox not configured")
            return None

        try:
            job_id = str(uuid.uuid4())
            filename = file_path.name

            logger.info(f"Submitting file {filename} to VM sandbox (Job: {job_id})")

            # Upload file via SFTP
            sftp = self._get_sftp()
            remote_file = f"{self._remote_upload_dir}/{job_id}_{filename}"

            logger.info(f"Uploading file to {remote_file}")
            sftp.put(str(file_path), remote_file)

            # Make executable if needed
            if filename.endswith(('.exe', '.dll', '.sh', '.py')):
                self._execute_command(f"chmod +x {remote_file}")

            # Create analysis script (not an f-string to avoid conflicts)
            analysis_script = """#!/bin/bash
# Malware Analysis Script for {}
# Job ID: {}

RESULT_FILE="{}/{}_result.json"
SAMPLE_FILE="{}"

echo "{{" > $RESULT_FILE
echo '  "job_id": "{}",' >> $RESULT_FILE
echo '  "filename": "{}",' >> $RESULT_FILE
echo '  "status": "running",' >> $RESULT_FILE
echo '  "start_time": "'$(date -Iseconds)'",' >> $RESULT_FILE

# Basic file analysis
echo '  "file_info": {{' >> $RESULT_FILE
echo '    "size": '$(stat -c%s "$SAMPLE_FILE")',' >> $RESULT_FILE
echo '    "type": "'$(file -b "$SAMPLE_FILE" | sed 's/"/\\\\"/g')'",' >> $RESULT_FILE
echo '    "md5": "'$(md5sum "$SAMPLE_FILE" | cut -d' ' -f1)'",' >> $RESULT_FILE
echo '    "sha256": "'$(sha256sum "$SAMPLE_FILE" | cut -d' ' -f1)'"' >> $RESULT_FILE
echo '  }},' >> $RESULT_FILE

# String extraction
echo '  "strings": [' >> $RESULT_FILE
strings "$SAMPLE_FILE" | head -100 | sed 's/"/\\\\"/g' | sed 's/^/    "/' | sed 's/$/",/' >> $RESULT_FILE
echo '    ""' >> $RESULT_FILE
echo '  ],' >> $RESULT_FILE

# Network monitoring (if tcpdump available)
if command -v tcpdump &> /dev/null; then
    echo '  "network_monitoring": "enabled",' >> $RESULT_FILE
else
    echo '  "network_monitoring": "disabled",' >> $RESULT_FILE
fi

# Process monitoring
echo '  "processes_before": [' >> $RESULT_FILE
ps aux | wc -l >> $RESULT_FILE
echo '  ],' >> $RESULT_FILE

echo '  "status": "completed",' >> $RESULT_FILE
echo '  "end_time": "'$(date -Iseconds)'"' >> $RESULT_FILE
echo "}" >> $RESULT_FILE

echo "Analysis complete for {}"
""".format(filename, job_id, self._remote_output_dir, job_id, remote_file, job_id, filename, filename)

            # Upload and execute analysis script
            script_path = f"{self._remote_upload_dir}/{job_id}_analyze.sh"
            sftp.file(script_path, 'w').write(analysis_script)

            self._execute_command(f"chmod +x {script_path}")

            # Execute analysis in background
            logger.info(f"Starting analysis for {filename}")
            self._execute_command(f"nohup {script_path} > /dev/null 2>&1 &")

            logger.info(f"File submitted successfully: Job {job_id}")
            return job_id

        except Exception as e:
            logger.error(f"File submission failed: {e}")
            return None

    def get_report(self, job_id: str) -> Optional[VMSandboxReport]:
        """
        Get analysis report from VM.

        Args:
            job_id: Job ID from submission

        Returns:
            VMSandboxReport if analysis complete
        """
        if not self.is_configured:
            return None

        try:
            result_file = f"{self._remote_output_dir}/{job_id}_result.json"

            # Check if result file exists
            stdout, stderr, exit_code = self._execute_command(f"test -f {result_file} && echo 'exists'")

            if "exists" not in stdout:
                # Analysis still pending
                return VMSandboxReport(job_id=job_id, status="pending")

            # Download result file
            sftp = self._get_sftp()
            with sftp.file(result_file, 'r') as f:
                result_data = json.loads(f.read())

            # Parse report
            report = VMSandboxReport(
                job_id=job_id,
                filename=result_data.get("filename", ""),
                status=result_data.get("status", "completed"),
                stdout=json.dumps(result_data, indent=2),
            )

            return report

        except Exception as e:
            logger.error(f"Failed to retrieve report: {e}")
            return VMSandboxReport(job_id=job_id, status="error", stderr=str(e))

    def get_state(self, job_id: str) -> str:
        """
        Get analysis state.

        Args:
            job_id: Job ID from submission

        Returns:
            State: pending, running, completed, error
        """
        report = self.get_report(job_id)
        return report.status if report else "unknown"

    def cleanup_job(self, job_id: str) -> bool:
        """
        Clean up job files from VM.

        Args:
            job_id: Job ID to clean up

        Returns:
            True if successful
        """
        try:
            self._execute_command(f"rm -f {self._remote_upload_dir}/{job_id}*")
            self._execute_command(f"rm -f {self._remote_output_dir}/{job_id}*")
            logger.info(f"Cleaned up job {job_id}")
            return True
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return False

    def close(self):
        """Close SSH and SFTP connections."""
        try:
            if self._sftp_client:
                self._sftp_client.close()
                self._sftp_client = None

            if self._ssh_client:
                self._ssh_client.close()
                self._ssh_client = None

            logger.info("Closed VM sandbox connection")
        except Exception as e:
            logger.error(f"Error closing connection: {e}")

    def __del__(self):
        """Cleanup on deletion."""
        self.close()
