# audit_logger.py - Fixed version
import json
import hashlib
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
import secrets

class AuditLogger:
    """
    Anonymous Authentication Audit Logger
    
    Features:
    - Daily log rotation
    - Anonymous user tracking with daily hash rotation
    - Local timezone logging
    - JSON structured logging
    - Privacy-focused (no personal data storage)
    """
    
    def __init__(self, log_directory="logs/audit", retention_days=30):
        self.log_directory = Path(log_directory)
        self.retention_days = retention_days
        self.current_date = None
        self.daily_salt = None
        
        # Setup logging infrastructure
        self.setup_directories()
        
        # Setup basic logging for audit system errors - FIXED
        self.setup_error_logging()
        
        # Setup daily rotation after error logging is ready
        self.setup_daily_rotation()
        
    def setup_directories(self):
        """Create log directories with proper permissions"""
        try:
            self.log_directory.mkdir(parents=True, exist_ok=True)
            
            # Set restrictive permissions on audit directory
            os.chmod(self.log_directory, 0o700)  # Owner only access
            
        except Exception as e:
            print(f"Warning: Could not setup audit log directory: {e}")
    
    def setup_error_logging(self):
        """Setup basic logging for audit system errors - FIXED"""
        try:
            error_log_file = self.log_directory / "audit_errors.log"
            
            # Create a separate logger for audit errors
            self.error_logger = logging.getLogger('audit_errors')
            
            # Avoid adding multiple handlers
            if not self.error_logger.handlers:
                handler = logging.FileHandler(error_log_file)
                handler.setFormatter(logging.Formatter('%(asctime)s | AUDIT_ERROR | %(message)s'))
                self.error_logger.addHandler(handler)
                self.error_logger.setLevel(logging.ERROR)
                
        except Exception as e:
            print(f"Warning: Could not setup audit error logging: {e}")
            # Create a minimal error logger that just prints
            self.error_logger = logging.getLogger('audit_errors_fallback')
    
    def setup_daily_rotation(self):
        """Setup daily log rotation and salt generation"""
        today = datetime.now().strftime('%Y_%m_%d')
        
        # Check if we need to rotate (new day)
        if self.current_date != today:
            self.current_date = today
            self.daily_salt = self.generate_daily_salt()
            self.rotate_logs()
    
    def generate_daily_salt(self):
        """Generate daily salt for hash anonymization"""
        # Use date as base for consistent daily salt
        date_seed = datetime.now().strftime('%Y-%m-%d')
        
        # Add some entropy while keeping it deterministic for the day
        salt_source = f"audit_salt_{date_seed}_pdf_manager"
        return hashlib.sha256(salt_source.encode()).hexdigest()[:16]
    
    def get_current_log_file(self):
        """Get current day's log file path"""
        return self.log_directory / f"auth_{self.current_date}.log"
    
    def get_current_symlink(self):
        """Get current log symlink path"""
        return self.log_directory / "auth_current.log"
    
    def rotate_logs(self):
        """Perform daily log rotation"""
        try:
            current_log = self.get_current_log_file()
            current_symlink = self.get_current_symlink()
            
            # Update symlink to point to today's log
            if current_symlink.exists() or current_symlink.is_symlink():
                current_symlink.unlink()
            
            # Create relative symlink
            relative_target = current_log.name
            current_symlink.symlink_to(relative_target)
            
            # Clean up old logs based on retention policy
            self.cleanup_old_logs()
            
        except Exception as e:
            if hasattr(self, 'error_logger'):
                self.error_logger.error(f"Log rotation failed: {e}")
            else:
                print(f"Log rotation failed: {e}")
    
    def cleanup_old_logs(self):
        """Remove logs older than retention period"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            
            for log_file in self.log_directory.glob("auth_*.log"):
                # Skip symlink
                if log_file.name == "auth_current.log":
                    continue
                
                # Extract date from filename: auth_2025_07_01.log
                try:
                    date_part = log_file.stem.replace("auth_", "")
                    file_date = datetime.strptime(date_part, "%Y_%m_%d")
                    
                    if file_date < cutoff_date:
                        log_file.unlink()
                        
                except (ValueError, OSError):
                    # Skip files that don't match expected format
                    continue
                    
        except Exception as e:
            if hasattr(self, 'error_logger'):
                self.error_logger.error(f"Log cleanup failed: {e}")
            else:
                print(f"Log cleanup failed: {e}")
    
    def hash_user_identifier(self, user_email):
        """Generate anonymous daily-rotating user hash"""
        if not user_email:
            return "anonymous"
        
        # Combine email with daily salt
        hash_source = f"{user_email.lower()}:{self.daily_salt}"
        user_hash = hashlib.sha256(hash_source.encode()).hexdigest()
        
        # Return first 12 characters for readability
        return f"user_{user_hash[:12]}"
    
    def hash_ip_address(self, ip_address):
        """Generate anonymous IP hash for geographic tracking"""
        if not ip_address:
            return "unknown_ip"
        
        # Hash IP with daily salt
        hash_source = f"{ip_address}:{self.daily_salt}"
        ip_hash = hashlib.sha256(hash_source.encode()).hexdigest()
        
        return f"ip_{ip_hash[:12]}"
    
    def hash_user_agent(self, user_agent):
        """Generate user agent hash for device fingerprinting"""
        if not user_agent:
            return "unknown_ua"
        
        # Hash user agent (no daily rotation - for device tracking)
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()
        
        return f"ua_{ua_hash[:12]}"
    
    def get_location_hint(self, ip_address):
        """Extract basic location hint without revealing specific location"""
        # For now, return general country-state hint
        # In production, you might use a GeoIP service
        return "IN-MH"  # India-Maharashtra (based on user location context)
    
    def assess_risk_level(self, event_type, context=None):
        """Basic risk level assessment for security events"""
        risk_mapping = {
            'AUTH_CSRF_ATTACK_DETECTED': 'HIGH',
            'AUTH_PKCE_VALIDATION_FAILURE': 'HIGH',
            'AUTH_LOGIN_FAILURE': 'MEDIUM',
            'AUTH_OAUTH_CALLBACK_FAILURE': 'MEDIUM',
            'AUTH_TOKEN_EXCHANGE_FAILURE': 'MEDIUM',
            'AUTH_LOGIN_SUCCESS': 'LOW',
            'AUTH_LOGIN_ATTEMPT': 'LOW',
            'AUTH_LOGOUT_INITIATED': 'LOW',
            'AUTH_OAUTH_CALLBACK_SUCCESS': 'LOW',
            'AUTH_TOKEN_EXCHANGE_SUCCESS': 'LOW'
        }
        
        return risk_mapping.get(event_type, 'LOW')
    
    def get_severity_level(self, risk_level):
        """Map risk level to log severity"""
        severity_mapping = {
            'LOW': 'INFO',
            'MEDIUM': 'WARN', 
            'HIGH': 'ERROR',
            'CRITICAL': 'ERROR'
        }
        
        return severity_mapping.get(risk_level, 'INFO')
    
    def create_log_entry(self, event_type, user_context=None, auth_details=None, 
                        request_context=None, additional_details=None):
        """Create structured anonymous log entry"""
        
        # Ensure daily rotation is current
        self.setup_daily_rotation()
        
        # Extract context safely
        user_context = user_context or {}
        auth_details = auth_details or {}
        request_context = request_context or {}
        
        # Generate anonymous identifiers
        user_email = user_context.get('user_email', '')
        ip_address = request_context.get('ip_address', '')
        user_agent = request_context.get('user_agent', '')
        
        user_hash = self.hash_user_identifier(user_email)
        ip_hash = self.hash_ip_address(ip_address)
        ua_hash = self.hash_user_agent(user_agent)
        location_hint = self.get_location_hint(ip_address)
        
        # Assess risk and severity
        risk_level = self.assess_risk_level(event_type, user_context)
        severity = self.get_severity_level(risk_level)
        
        # Create structured log entry
        log_entry = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            "event_type": event_type,
            "severity": severity,
            "user_hash": user_hash,
            "request_context": {
                "ip_hash": ip_hash,
                "user_agent_hash": ua_hash,
                "location_hint": location_hint
            },
            "auth_details": {
                "oauth_provider": auth_details.get('oauth_provider', 'google'),
                "method": auth_details.get('method', 'pkce'),
                "scopes": auth_details.get('scopes', ['openid', 'email', 'profile'])
            },
            "security_metrics": {
                "risk_level": risk_level
            }
        }
        
        # Add additional details if provided
        if additional_details:
            log_entry["additional_details"] = additional_details
        
        return log_entry
    
    def write_log_entry(self, log_entry):
        """Write log entry to current log file"""
        try:
            log_file = self.get_current_log_file()
            
            # Convert to JSON string
            log_line = json.dumps(log_entry, separators=(',', ':'))
            
            # Write to file (JSON Lines format)
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_line + '\n')
            
            # Set restrictive permissions on log file
            os.chmod(log_file, 0o600)  # Owner read/write only
            
        except Exception as e:
            if hasattr(self, 'error_logger'):
                self.error_logger.error(f"Failed to write log entry: {e}")
            else:
                print(f"Failed to write log entry: {e}")
            # Don't raise exception - logging failures shouldn't break app
    
    def log_auth_event(self, event_type, user_context=None, auth_details=None, 
                      request_context=None, additional_details=None):
        """
        Main method to log authentication events
        
        Args:
            event_type (str): Type of auth event (AUTH_LOGIN_SUCCESS, etc.)
            user_context (dict): User information (will be anonymized)
            auth_details (dict): OAuth/authentication specific details
            request_context (dict): Request information (IP, user agent, etc.)
            additional_details (dict): Any additional context
        """
        try:
            # Create anonymous log entry
            log_entry = self.create_log_entry(
                event_type=event_type,
                user_context=user_context,
                auth_details=auth_details,
                request_context=request_context,
                additional_details=additional_details
            )
            
            # Write to log file
            self.write_log_entry(log_entry)
            
        except Exception as e:
            if hasattr(self, 'error_logger'):
                self.error_logger.error(f"Failed to log auth event {event_type}: {e}")
            else:
                print(f"Failed to log auth event {event_type}: {e}")
            # Continue gracefully - don't break authentication flow
    
    def log_login_attempt(self, request_context=None):
        """Log login attempt event"""
        self.log_auth_event(
            event_type="AUTH_LOGIN_ATTEMPT",
            request_context=request_context,
            auth_details={"method": "oauth2_pkce"}
        )
    
    def log_login_success(self, user_context=None, request_context=None):
        """Log successful login event"""
        self.log_auth_event(
            event_type="AUTH_LOGIN_SUCCESS",
            user_context=user_context,
            request_context=request_context,
            auth_details={"method": "oauth2_pkce"}
        )
    
    def log_login_failure(self, reason, user_context=None, request_context=None):
        """Log failed login event"""
        self.log_auth_event(
            event_type="AUTH_LOGIN_FAILURE",
            user_context=user_context,
            request_context=request_context,
            additional_details={"failure_reason": reason}
        )
    
    def log_logout(self, user_context=None, request_context=None):
        """Log logout event"""
        self.log_auth_event(
            event_type="AUTH_LOGOUT_INITIATED",
            user_context=user_context,
            request_context=request_context
        )
    
    def log_csrf_attack(self, request_context=None, attack_details=None):
        """Log CSRF attack attempt"""
        self.log_auth_event(
            event_type="AUTH_CSRF_ATTACK_DETECTED",
            request_context=request_context,
            additional_details=attack_details or {"attack_type": "invalid_state"}
        )
    
    def log_oauth_callback_start(self, request_context=None):
        """Log OAuth callback start"""
        self.log_auth_event(
            event_type="AUTH_OAUTH_CALLBACK_START",
            request_context=request_context
        )
    
    def log_oauth_callback_success(self, user_context=None, request_context=None):
        """Log OAuth callback success"""
        self.log_auth_event(
            event_type="AUTH_OAUTH_CALLBACK_SUCCESS",
            user_context=user_context,
            request_context=request_context
        )
    
    def log_oauth_callback_failure(self, reason, request_context=None):
        """Log OAuth callback failure"""
        self.log_auth_event(
            event_type="AUTH_OAUTH_CALLBACK_FAILURE",
            request_context=request_context,
            additional_details={"failure_reason": reason}
        )
    
    def log_token_exchange_success(self, user_context=None, request_context=None):
        """Log successful token exchange"""
        self.log_auth_event(
            event_type="AUTH_TOKEN_EXCHANGE_SUCCESS",
            user_context=user_context,
            request_context=request_context
        )
    
    def log_token_exchange_failure(self, reason, request_context=None):
        """Log failed token exchange"""
        self.log_auth_event(
            event_type="AUTH_TOKEN_EXCHANGE_FAILURE",
            request_context=request_context,
            additional_details={"failure_reason": reason}
        )
    
    def log_pkce_validation_failure(self, request_context=None):
        """Log PKCE validation failure"""
        self.log_auth_event(
            event_type="AUTH_PKCE_VALIDATION_FAILURE",
            request_context=request_context,
            additional_details={"validation_type": "pkce_code_verifier"}
        )