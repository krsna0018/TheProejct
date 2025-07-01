import streamlit as st
import requests
import json
import os
import secrets
import hashlib
import base64
import logging
from urllib.parse import urlencode, parse_qs, urlparse
from dotenv import load_dotenv
from pathlib import Path

# Import audit logger
try:
    from audit_logger import AuditLogger
    AUDIT_LOGGING_AVAILABLE = True
except ImportError:
    AUDIT_LOGGING_AVAILABLE = False
    print("Warning: audit_logger not available - audit logging disabled")

# Load environment variables
load_dotenv()

# FIXED: Simple logger that inherits from the root logger set up in app.py
logger = logging.getLogger(__name__)

class GoogleOAuth:
    def __init__(self):
        logger.info("🔧 Initializing GoogleOAuth class with PKCE support and audit logging")
        self.client_id = os.getenv('GOOGLE_CLIENT_ID')
        self.client_secret = os.getenv('GOOGLE_CLIENT_SECRET')  # Still needed for token exchange
        self.redirect_uri = os.getenv('REDIRECT_URI')
        self.users_file = 'users.json'
        
        # Log environment status
        logger.info(f"🔧 Environment - CLIENT_ID exists: {bool(self.client_id)}")
        logger.info(f"🔧 Environment - CLIENT_SECRET exists: {bool(self.client_secret)}")
        logger.info(f"🔧 Environment - REDIRECT_URI: {self.redirect_uri}")
        
        # Initialize audit logger
        if AUDIT_LOGGING_AVAILABLE:
            try:
                self.audit_logger = AuditLogger()
                logger.info("✅ Audit logging initialized successfully")
            except Exception as e:
                logger.warning(f"⚠️ Audit logger initialization failed: {e}")
                self.audit_logger = None
        else:
            self.audit_logger = None
            
    def safe_audit_log(self, method_name, **kwargs):
        """Safely call audit logging function without breaking auth flow"""
        if not self.audit_logger:
            return
            
        try:
            method = getattr(self.audit_logger, method_name, None)
            if method and callable(method):
                method(**kwargs)
        except Exception as e:
            logger.warning(f"Audit logging failed: {e}")
            # Continue gracefully - don't break authentication
    
    def get_client_ip(self):
        """Extract client IP address from Streamlit context"""
        try:
            # Streamlit doesn't expose client IP directly in standard deployment
            # This would need to be implemented based on your deployment setup
            
            # For development/local testing
            if os.getenv('STREAMLIT_ENV') == 'development':
                return "127.0.0.1"
            
            # For production deployments, you might need to:
            # 1. Use reverse proxy headers (X-Forwarded-For, X-Real-IP)
            # 2. Access through streamlit context if available
            # 3. Use request headers if accessible
            
            # Placeholder implementation - replace with actual IP extraction
            return "unknown"
            
        except Exception:
            return "unknown"
    
    def get_user_agent(self):
        """Extract user agent from request context"""
        try:
            # Streamlit doesn't directly expose user agent in standard setup
            # This would need custom implementation based on deployment
            
            # Placeholder implementation - replace with actual user agent extraction
            # In production, you might access this through:
            # 1. Custom middleware
            # 2. JavaScript bridge to get navigator.userAgent
            # 3. Server-side request headers if accessible
            
            return "streamlit_app"
            
        except Exception:
            return "unknown"
    
    def get_request_context(self):
        """Collect request context for audit logging"""
        return {
            'ip_address': self.get_client_ip(),
            'user_agent': self.get_user_agent()
        }
    
    def get_user_context(self, user_info):
        """Collect user context for audit logging"""
        if not user_info:
            return {}
        
        return {
            'user_email': user_info.get('email', '')
        }
        
    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge pair"""
        # Generate code verifier (128 characters, URL-safe)
        code_verifier = secrets.token_urlsafe(96)  # 96 bytes = 128 chars when base64 encoded
        
        # Generate code challenge (SHA256 hash of verifier)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        
        logger.info("🛡️ PKCE parameters generated successfully")
        return code_verifier, code_challenge
        
    def generate_auth_url(self):
        """Generate Google OAuth authorization URL with PKCE"""
        logger.info("🚀 Starting OAuth URL generation with PKCE")
        
        # Log login attempt
        request_context = self.get_request_context()
        self.safe_audit_log('log_login_attempt', request_context=request_context)
        
        # Generate PKCE parameters
        code_verifier, code_challenge = self.generate_pkce_pair()
        
        # Generate state parameter for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Store both in session AND as backup in query params
        st.session_state['oauth_state'] = state
        st.session_state['code_verifier'] = code_verifier
        
        # Also store in a temporary file as backup (for session persistence issues)
        temp_oauth_file = Path("temp_oauth_state.json")
        try:
            with open(temp_oauth_file, 'w') as f:
                json.dump({
                    'state': state,
                    'code_verifier': code_verifier,
                    'timestamp': 'recent'
                }, f)
        except:
            pass  # Continue even if file storage fails
        
        logger.info("🔑 Generated OAuth state and PKCE verifier")
        
        # Build authorization URL with PKCE parameters
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid email profile',
            'response_type': 'code',
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',  # SHA256 method
            'access_type': 'offline',  # Still request refresh capability
            'prompt': 'consent'
        }
        
        auth_url = f"https://accounts.google.com/o/oauth2/auth?{urlencode(params)}"
        logger.info("✅ Successfully generated PKCE-secured OAuth URL")
        
        return auth_url
    
    def handle_callback(self, code, state):
        """Handle OAuth callback and exchange code for tokens using PKCE"""
        logger.info("🔄 Starting OAuth callback handling with PKCE")
        
        # Log OAuth callback start
        request_context = self.get_request_context()
        self.safe_audit_log('log_oauth_callback_start', request_context=request_context)
        
        # First try to get state and verifier from session
        stored_state = st.session_state.get('oauth_state')
        code_verifier = st.session_state.get('code_verifier')
        
        # If not in session, try to recover from temp file
        if not stored_state or not code_verifier:
            temp_oauth_file = Path("temp_oauth_state.json")
            try:
                if temp_oauth_file.exists():
                    with open(temp_oauth_file, 'r') as f:
                        temp_data = json.load(f)
                    stored_state = temp_data.get('state')
                    code_verifier = temp_data.get('code_verifier')
                    logger.info("🔄 Recovered OAuth state from temporary storage")
            except:
                pass
        
        # Verify state parameter (CSRF protection)
        if not state or state != stored_state:
            logger.error("❌ Error: Invalid or missing state parameter")
            
            # Log CSRF attack attempt
            attack_details = {
                'provided_state': state[:10] if state else 'None',
                'expected_state_exists': bool(stored_state),
                'attack_type': 'invalid_state_parameter'
            }
            self.safe_audit_log('log_csrf_attack', 
                              request_context=request_context,
                              attack_details=attack_details)
            
            return False, "Invalid state parameter - possible CSRF attack"
        
        # Verify code verifier exists
        if not code_verifier:
            logger.error("❌ Error: Code verifier not found")
            
            # Log PKCE validation failure
            self.safe_audit_log('log_pkce_validation_failure', request_context=request_context)
            
            return False, "Authentication session expired. Please try again."
        
        logger.info("🛡️ PKCE verification successful - exchanging code for tokens")
        
        # Exchange authorization code for tokens using PKCE
        token_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,  # Still needed for this step
            'code': code,
            'code_verifier': code_verifier,  # PKCE verifier instead of just client_secret
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri,
        }
        
        try:
            token_response = requests.post(
                'https://oauth2.googleapis.com/token',
                data=token_data,
                timeout=30
            )
            token_response.raise_for_status()
            tokens = token_response.json()
            
            logger.info("✅ Successfully received tokens from Google")
            
            # Log successful token exchange
            self.safe_audit_log('log_token_exchange_success', request_context=request_context)
            
            # Get user info using access token
            user_info_response = requests.get(
                'https://www.googleapis.com/oauth2/v2/userinfo',
                headers={'Authorization': f"Bearer {tokens['access_token']}"},
                timeout=30
            )
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            
            logger.info(f"✅ Successfully retrieved user info for: {user_info.get('email', 'Unknown')}")
            
            # Log successful login
            user_context = self.get_user_context(user_info)
            self.safe_audit_log('log_login_success',
                              user_context=user_context,
                              request_context=request_context)
            
            # Store user info in session (NOT storing refresh token for security)
            self.store_user_session(user_info, tokens)
            self.save_user_to_file(user_info)
            
            # Clean up PKCE parameters and temp files
            keys_to_clear = ['code_verifier', 'oauth_state']
            for key in keys_to_clear:
                if key in st.session_state:
                    del st.session_state[key]
            
            # Remove temp file
            temp_oauth_file = Path("temp_oauth_state.json")
            try:
                if temp_oauth_file.exists():
                    temp_oauth_file.unlink()
            except:
                pass
            
            # Log successful OAuth callback
            self.safe_audit_log('log_oauth_callback_success',
                              user_context=user_context,
                              request_context=request_context)
            
            logger.info("🎉 OAuth callback handling completed successfully")
            return True, "Authentication successful"
            
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ OAuth callback failed: {str(e)}")
            
            # Log token exchange failure
            self.safe_audit_log('log_token_exchange_failure',
                              reason=str(e),
                              request_context=request_context)
            
            # Log overall login failure
            self.safe_audit_log('log_login_failure',
                              reason=f"Token exchange failed: {str(e)}",
                              request_context=request_context)
            
            # Log OAuth callback failure
            self.safe_audit_log('log_oauth_callback_failure',
                              reason=str(e),
                              request_context=request_context)
            
            return False, f"Authentication failed: {str(e)}"
        
        except Exception as e:
            logger.error(f"❌ Unexpected error during OAuth callback: {str(e)}")
            
            # Log unexpected login failure
            self.safe_audit_log('log_login_failure',
                              reason=f"Unexpected error: {str(e)}",
                              request_context=request_context)
            
            return False, f"Authentication failed: {str(e)}"
    
    def store_user_session(self, user_info, tokens):
        """Store user information in Streamlit session"""
        st.session_state['authenticated'] = True
        st.session_state['user_id'] = user_info['id']
        st.session_state['user_email'] = user_info['email']
        st.session_state['user_name'] = user_info['name']
        st.session_state['user_picture'] = user_info.get('picture', '')
        st.session_state['access_token'] = tokens['access_token']
    
    def generate_folder_name(self, user_name, user_id):
        """Generate folder name using first 4 letters of name + last 4 digits of hash"""
        logger.info(f"📁 Generating folder name for user: {user_name}")
        
        # Get first 4 characters of name (remove spaces, convert to lowercase)
        clean_name = user_name.replace(" ", "").lower()
        first_part = clean_name[:4] if len(clean_name) >= 4 else clean_name
        
        # Generate hash of user_id and get last 4 characters
        user_hash = hashlib.md5(user_id.encode()).hexdigest()
        last_part = user_hash[-4:]
        
        # Combine with underscore
        folder_name = f"{first_part}_{last_part}"
        
        logger.info(f"📝 Name processing: '{user_name}' -> '{clean_name}' -> '{first_part}'")
        logger.info(f"🔐 Hash processing: User ID -> {user_hash} -> {last_part}")
        logger.info(f"✅ Generated folder name: {folder_name}")
        
        return folder_name
    
    def save_user_to_file(self, user_info):
        """Save user information to JSON file"""
        try:
            # Generate custom folder name
            folder_name = self.generate_folder_name(user_info['name'], user_info['id'])
            
            # Load existing users
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    users = json.load(f)
            else:
                users = {}
            
            # Add/update user with folder name
            users[user_info['id']] = {
                'email': user_info['email'],
                'name': user_info['name'],
                'picture': user_info.get('picture', ''),
                'folder_name': folder_name,
                'last_login': 'recent'
            }
            
            # Save back to file
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=2, ensure_ascii=False)
                
            # Create user directory with custom name
            user_dir = Path(f"data/{folder_name}")
            user_dir.mkdir(parents=True, exist_ok=True)
            
            # Store folder name in session
            st.session_state['user_folder'] = folder_name
                
        except Exception as e:
            logger.error(f"Error saving user data: {str(e)}")
            st.error(f"Error saving user data: {str(e)}")
    
    def is_authenticated(self):
        """Check if user is authenticated"""
        auth_status = st.session_state.get('authenticated', False)
        logger.info(f"🔍 Authentication check: {auth_status}")
        return auth_status
    
    def get_user_info(self):
        """Get current user information"""
        logger.info("📋 Retrieving user information from session")
        
        if self.is_authenticated():
            user_info = {
                'id': st.session_state.get('user_id'),
                'email': st.session_state.get('user_email'),
                'name': st.session_state.get('user_name'),
                'picture': st.session_state.get('user_picture')
            }
            logger.info(f"👤 User info retrieved: {user_info['email']}")
            return user_info
        
        logger.info("❌ No authenticated user found")
        return None
    
    def logout(self):
        """Logout user and clear session"""
        logger.info("🚪 Starting user logout process")
        
        # Get current user context before clearing session for audit logging
        user_info = self.get_user_info()
        user_email = st.session_state.get('user_email', 'Unknown')
        logger.info(f"👋 Logging out user: {user_email}")
        
        # Log logout event
        if user_info:
            user_context = self.get_user_context(user_info)
            request_context = self.get_request_context()
            self.safe_audit_log('log_logout',
                              user_context=user_context,
                              request_context=request_context)
        
        keys_to_clear = [
            'authenticated', 'user_id', 'user_email', 
            'user_name', 'user_picture', 'access_token', 'oauth_state', 'user_folder'
        ]
        
        cleared_keys = []
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]
                cleared_keys.append(key)
        
        logger.info(f"🧹 Cleared session keys: {cleared_keys}")
        logger.info("✅ Logout completed successfully")
        
        st.rerun()
    
    def get_user_directory(self):
        """Get user's data directory path"""
        logger.info("📁 Getting user directory path")
        
        if self.is_authenticated():
            # First try to get folder name from session
            folder_name = st.session_state.get('user_folder')
            
            # If not in session, look it up from users.json
            if not folder_name:
                user_id = st.session_state.get('user_id')
                user_name = st.session_state.get('user_name')
                logger.info(f"🔍 Folder name not in session, generating for: {user_name}")
                
                if user_id and user_name:
                    folder_name = self.generate_folder_name(user_name, user_id)
                    st.session_state['user_folder'] = folder_name
                    logger.info(f"💾 Generated and stored folder name: {folder_name}")
            
            if folder_name:
                user_dir = Path(f"data/{folder_name}")
                logger.info(f"📂 User directory path: {user_dir}")
                return user_dir
        
        logger.info("❌ No user directory available - user not authenticated")
        return None
    
    def test_audit_logging(self):
        """Test audit logging functionality"""
        print("=== AUDIT LOGGING TEST ===")
        print(f"Audit logger available: {self.audit_logger is not None}")
        
        if self.audit_logger:
            return self.audit_logger.test_logging()
        else:
            print("❌ Audit logger not available")
            return False