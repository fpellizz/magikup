"""
SSM Tunnel management module.
Handles creating and managing SSM port forwarding sessions.
"""

import re
import subprocess
import socket
import time
import os
import signal
import logging
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
from threading import Lock

from .config import get_aws_config

logger = logging.getLogger(__name__)

# Hostnames/IPs allowed as the SSM remote target. Restricting the charset to
# valid hostname/IP characters prevents injection into the --parameters JSON
# document passed to the AWS CLI (which is built by string interpolation).
_HOST_RE = re.compile(r'^[A-Za-z0-9._-]+$')


def _validate_remote_target(remote_host: str, remote_port: int) -> Optional[str]:
    """Validate the tunnel target. Returns an error string, or None if valid."""
    if not remote_host or not isinstance(remote_host, str):
        return "Remote host is required"
    if len(remote_host) > 253 or not _HOST_RE.match(remote_host):
        return "Invalid remote host: only letters, digits, '.', '-' and '_' are allowed"
    try:
        port = int(remote_port)
    except (TypeError, ValueError):
        return "Invalid remote port"
    if not (1 <= port <= 65535):
        return "Remote port must be between 1 and 65535"
    return None


@dataclass
class TunnelInfo:
    """Information about an active SSM tunnel."""
    tunnel_id: str
    remote_host: str
    remote_port: int
    local_port: int
    jumphost_id: str
    process: subprocess.Popen
    status: str = "starting"
    aws_account_alias: str = ""


class SSMTunnelManager:
    """Manages SSM port forwarding tunnels."""

    _instance = None
    _lock = Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._tunnels: Dict[str, TunnelInfo] = {}
        self._port_counter = 15432
        self._initialized = True

    def _find_available_port(self, start_port: int = 15432) -> int:
        """Find an available local port."""
        port = start_port
        while port < 65535:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('localhost', port))
                sock.close()
                return port
            except OSError:
                port += 1
        raise RuntimeError("No available ports found")

    def _wait_for_port(self, port: int, timeout: int = 30) -> bool:
        """Wait for a port to become open (tunnel ready)."""
        logger.info(f"Waiting for port {port} to be ready (timeout: {timeout}s)")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                if result == 0:
                    logger.info(f"Port {port} is now open")
                    return True
            except Exception as e:
                logger.debug(f"Port check failed: {e}")
            time.sleep(1)
        logger.warning(f"Port {port} did not open within {timeout}s")
        return False

    def _generate_tunnel_id(self, remote_host: str, remote_port: int) -> str:
        """Generate a unique tunnel ID."""
        return f"{remote_host}:{remote_port}"

    def start_tunnel(
        self,
        remote_host: str,
        remote_port: int = 5432,
        local_port: Optional[int] = None,
        jumphost_id: Optional[str] = None,
        aws_account_alias: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Start an SSM port forwarding tunnel.

        Args:
            remote_host: The remote database endpoint
            remote_port: The remote database port (default 5432)
            local_port: Optional local port (auto-assigned if not provided)
            jumphost_id: Optional jumphost instance ID
            aws_account_alias: AWS account alias for credentials

        Returns:
            Dict with tunnel information or error
        """
        target_error = _validate_remote_target(remote_host, remote_port)
        if target_error:
            logger.warning(f"Rejected tunnel request: {target_error} (host={remote_host!r})")
            return {"success": False, "error": target_error}

        if not jumphost_id:
            logger.error("No jumphost ID configured")
            return {
                "success": False,
                "error": "No jumphost ID configured. Set it in Admin settings.",
            }

        tunnel_id = self._generate_tunnel_id(remote_host, remote_port)
        logger.info(f"Starting tunnel {tunnel_id} via jumphost {jumphost_id}")

        if tunnel_id in self._tunnels:
            tunnel = self._tunnels[tunnel_id]
            if tunnel.process.poll() is None:
                logger.info(f"Tunnel {tunnel_id} already active on port {tunnel.local_port}")
                return {
                    "success": True,
                    "tunnel_id": tunnel_id,
                    "local_port": tunnel.local_port,
                    "message": "Tunnel already active",
                }
            else:
                logger.warning(f"Tunnel {tunnel_id} was dead, removing and recreating")
                del self._tunnels[tunnel_id]

        if local_port is None:
            local_port = self._find_available_port()
            logger.debug(f"Auto-assigned local port {local_port}")

        aws_config = get_aws_config(alias=aws_account_alias)
        if not aws_config:
            return {
                "success": False,
                "error": f"AWS account '{aws_account_alias or 'default'}' not configured.",
            }

        env = os.environ.copy()
        if aws_config.access_key_id:
            env['AWS_ACCESS_KEY_ID'] = aws_config.access_key_id
        if aws_config.secret_access_key:
            env['AWS_SECRET_ACCESS_KEY'] = aws_config.secret_access_key
        if aws_config.region:
            env['AWS_DEFAULT_REGION'] = aws_config.region

        cmd = [
            'aws', 'ssm', 'start-session',
            '--target', jumphost_id,
            '--document-name', 'AWS-StartPortForwardingSessionToRemoteHost',
            '--parameters', f'{{"host":["{remote_host}"],"portNumber":["{remote_port}"],"localPortNumber":["{local_port}"]}}',
            '--region', aws_config.region or 'us-east-1',
        ]

        logger.info(f"Executing SSM command: {' '.join(cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=os.setsid,
            )

            logger.debug(f"SSM process started with PID {process.pid}")

            # Wait for the port to become available (tunnel established)
            if not self._wait_for_port(local_port, timeout=30):
                # Port didn't open, check if process died
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    stdout_msg = stdout.decode().strip() if stdout else ""
                    stderr_msg = stderr.decode().strip() if stderr else ""
                    logger.error(f"Tunnel process died. Stdout: {stdout_msg}, Stderr: {stderr_msg}")
                    return {
                        "success": False,
                        "error": f"Tunnel failed to start. Process exited. Stderr: {stderr_msg or 'No error message'}",
                    }
                else:
                    # Process is alive but port not open
                    logger.error(f"Tunnel process running but port {local_port} not accessible")
                    # Kill the process since it's not working
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    except:
                        pass
                    return {
                        "success": False,
                        "error": f"Tunnel process started but port {local_port} not accessible. Check if jumphost can reach {remote_host}.",
                    }

            # Double check process is still alive
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                logger.error(f"Tunnel process died after port opened. Stderr: {stderr.decode()}")
                return {
                    "success": False,
                    "error": "Tunnel process died unexpectedly",
                }

            tunnel_info = TunnelInfo(
                tunnel_id=tunnel_id,
                remote_host=remote_host,
                remote_port=remote_port,
                local_port=local_port,
                jumphost_id=jumphost_id,
                process=process,
                status="active",
                aws_account_alias=aws_account_alias or "",
            )
            self._tunnels[tunnel_id] = tunnel_info

            logger.info(f"Tunnel {tunnel_id} successfully started on local port {local_port}")

            return {
                "success": True,
                "tunnel_id": tunnel_id,
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
            }

        except FileNotFoundError as e:
            logger.error(f"AWS CLI or session-manager-plugin not found: {e}")
            return {
                "success": False,
                "error": "AWS CLI not found. Please install AWS CLI and session-manager-plugin.",
            }
        except Exception as e:
            logger.exception(f"Unexpected error starting tunnel: {e}")
            return {
                "success": False,
                "error": f"Failed to start tunnel: {str(e)}",
            }

    def stop_tunnel(self, tunnel_id: str) -> Dict[str, Any]:
        """Stop an active tunnel."""
        if tunnel_id not in self._tunnels:
            logger.warning(f"Attempted to stop non-existent tunnel: {tunnel_id}")
            return {
                "success": False,
                "error": "Tunnel not found",
            }

        tunnel = self._tunnels[tunnel_id]
        logger.info(f"Stopping tunnel {tunnel_id}")

        try:
            os.killpg(os.getpgid(tunnel.process.pid), signal.SIGTERM)
            tunnel.process.wait(timeout=5)
            logger.debug(f"Tunnel {tunnel_id} terminated gracefully")
        except ProcessLookupError:
            logger.debug(f"Process for tunnel {tunnel_id} already dead")
            pass
        except subprocess.TimeoutExpired:
            logger.warning(f"Tunnel {tunnel_id} didn't stop gracefully, forcing kill")
            os.killpg(os.getpgid(tunnel.process.pid), signal.SIGKILL)
        except Exception as e:
            logger.error(f"Failed to stop tunnel {tunnel_id}: {e}")
            return {
                "success": False,
                "error": f"Failed to stop tunnel: {str(e)}",
            }

        del self._tunnels[tunnel_id]
        logger.info(f"Tunnel {tunnel_id} stopped successfully")
        return {
            "success": True,
            "message": f"Tunnel {tunnel_id} stopped",
        }

    def get_tunnel(self, tunnel_id: str) -> Optional[TunnelInfo]:
        """Get tunnel information."""
        return self._tunnels.get(tunnel_id)

    def get_tunnel_for_endpoint(self, remote_host: str, remote_port: int = 5432) -> Optional[TunnelInfo]:
        """Get tunnel for a specific endpoint if it exists."""
        tunnel_id = self._generate_tunnel_id(remote_host, remote_port)
        tunnel = self._tunnels.get(tunnel_id)
        if tunnel and tunnel.process.poll() is None:
            return tunnel
        return None

    def list_tunnels(self) -> List[Dict[str, Any]]:
        """List all active tunnels."""
        active_tunnels = []
        to_remove = []

        for tunnel_id, tunnel in self._tunnels.items():
            if tunnel.process.poll() is None:
                active_tunnels.append({
                    "tunnel_id": tunnel_id,
                    "remote_host": tunnel.remote_host,
                    "remote_port": tunnel.remote_port,
                    "local_port": tunnel.local_port,
                    "jumphost_id": tunnel.jumphost_id,
                    "status": "active",
                })
            else:
                logger.warning(f"Tunnel {tunnel_id} died unexpectedly, removing from list")
                to_remove.append(tunnel_id)

        for tunnel_id in to_remove:
            del self._tunnels[tunnel_id]

        logger.debug(f"Active tunnels: {len(active_tunnels)}")
        return active_tunnels

    def stop_all_tunnels(self) -> None:
        """Stop all active tunnels."""
        for tunnel_id in list(self._tunnels.keys()):
            self.stop_tunnel(tunnel_id)


tunnel_manager = SSMTunnelManager()
