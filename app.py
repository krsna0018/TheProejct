import streamlit as st
import os
import logging
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from dotenv import load_dotenv
import base64

# Load environment variables FIRST
load_dotenv()

# FIXED LOGGING SETUP
def setup_simple_logging():
    """Simple logging setup that actually works"""
    
    # Clear existing handlers to avoid conflicts
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Get debug mode
    debug_mode = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
    
    # Print to console so you can see what's happening
    print(f"🔧 DEBUG_MODE from env: '{os.getenv('DEBUG_MODE')}'")
    print(f"🔧 DEBUG_MODE as boolean: {debug_mode}")
    
    if debug_mode:
        # Simple logging setup without restrictive filters
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(funcName)s | %(message)s',
            force=True
        )
        logger = logging.getLogger(__name__)
        logger.info("🚀 LOGGING ACTIVATED - Debug mode enabled")
        logger.info(f"✅ Environment DEBUG_MODE: {os.getenv('DEBUG_MODE')}")
        logger.info(f"✅ Client ID exists: {bool(os.getenv('GOOGLE_CLIENT_ID'))}")
        print("🔧 Logging has been activated - check terminal for log messages")
        return logger
    else:
        logging.basicConfig(level=logging.WARNING, force=True)
        logger = logging.getLogger(__name__)
        print("⚠️ DEBUG_MODE is FALSE - limited logging")
        return logger

# Setup logging
logger = setup_simple_logging()

# Import auth AFTER logging is setup
from auth import GoogleOAuth

# Page configuration
st.set_page_config(
    page_title="PDF Manager",
    page_icon="📄",
    layout="wide"
)

# Initialize OAuth handler
logger.info("🚀 Initializing PDF Manager application")
oauth = GoogleOAuth()

def handle_oauth_callback():
    """Handle OAuth callback from URL parameters"""
    logger.info("🔄 Checking for OAuth callback parameters")
    
    # Check if we have OAuth callback parameters
    query_params = st.query_params
    logger.info(f"📥 Query parameters found: {bool(query_params)}")
    
    if 'code' in query_params and 'state' in query_params:
        code = query_params['code']
        state = query_params['state']
        
        logger.info("✅ OAuth callback parameters found, processing...")
        logger.info(f"📝 Code length: {len(code) if code else 0}")
        logger.info(f"📝 State length: {len(state) if state else 0}")
        
        success, message = oauth.handle_callback(code, state)
        
        if success:
            logger.info("🎉 OAuth callback successful")
            st.success("✅ Login successful! Welcome!")
            # Clear URL parameters
            st.query_params.clear()
            logger.info("🧹 Cleared URL parameters")
            st.rerun()
        else:
            logger.error(f"❌ OAuth callback failed: {message}")
            st.error(f"❌ Login failed: {message}")
            st.query_params.clear()
    else:
        logger.info("ℹ️ No OAuth callback parameters found")

def show_login_page():
    """Display login page"""
    logger.info("🔐 Displaying login page")
    
    st.title("🔐 PDF Manager - Login Required")
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        ### Welcome to PDF Manager
        
        **Features:**
        - 📤 Upload PDF files
        - 📁 View your uploaded files
        - 📥 Download your files
        - 🔒 Secure personal storage
        
        Please login with Google to continue.
        """)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Login button
        logger.info("🔗 Generating Google OAuth URL")
        auth_url = oauth.generate_auth_url()
        logger.info("🌐 OAuth URL generated successfully")
        
        st.markdown(f"""
        <div style="text-align: center;">
            <a href="{auth_url}" target="_self">
                <button style="
                    background-color: #4285f4;
                    color: white;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 6px;
                    font-size: 16px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                ">
                    🔑 Login with Google
                </button>
            </a>
        </div>
        """, unsafe_allow_html=True)

def show_main_app():
    """Display main application interface"""
    logger.info("🏠 Displaying main application interface")
    
    user_info = oauth.get_user_info()
    user_dir = oauth.get_user_directory()
    
    logger.info(f"👤 Current user: {user_info['email'] if user_info else 'None'}")
    logger.info(f"📁 User directory: {user_dir}")
    
    # Header
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.title(f"📄 PDF Manager - Welcome, {user_info['name']}!")
    
    with col2:
        if st.button("🚪 Logout"):
            logger.info("🚪 User initiated logout")
            oauth.logout()
    
    # User info
    with st.expander("👤 User Profile", expanded=False):
        col1, col2 = st.columns([1, 3])
        with col1:
            if user_info['picture']:
                st.image(user_info['picture'], width=80)
        with col2:
            st.write(f"**Name:** {user_info['name']}")
            st.write(f"**Email:** {user_info['email']}")
            st.write(f"**User ID:** {user_info['id']}")
            folder_name = st.session_state.get('user_folder', 'Not set')
            st.write(f"**Folder:** {folder_name}")
            logger.info(f"📋 Displayed user profile for: {user_info['email']}")
    
    st.markdown("---")
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["📤 Upload PDF", "📁 My Files", "📊 Statistics"])
    
    with tab1:
        logger.info("📤 Displaying upload tab")
        st.header("Upload PDF Files")
        
        uploaded_files = st.file_uploader(
            "Choose PDF files",
            type=['pdf'],
            accept_multiple_files=True,
            help="Upload one or more PDF files to your personal storage"
        )
        
        if uploaded_files:
            logger.info(f"📥 User selected {len(uploaded_files)} files for upload")
            for uploaded_file in uploaded_files:
                logger.info(f"📄 Processing file: {uploaded_file.name} ({uploaded_file.size} bytes)")
                
                if st.button(f"Save {uploaded_file.name}", key=f"save_{uploaded_file.name}"):
                    logger.info(f"💾 Starting save process for: {uploaded_file.name}")
                    try:
                        # Ensure user directory exists
                        user_dir.mkdir(parents=True, exist_ok=True)
                        logger.info(f"📁 User directory verified: {user_dir}")
                        
                        # Save file to user directory
                        file_path = user_dir / uploaded_file.name
                        logger.info(f"💾 Saving to: {file_path}")
                        
                        with open(file_path, "wb") as f:
                            f.write(uploaded_file.getbuffer())
                        
                        logger.info(f"✅ File saved successfully: {uploaded_file.name}")
                        st.success(f"✅ {uploaded_file.name} saved successfully!")
                        st.rerun()
                        
                    except Exception as e:
                        logger.error(f"❌ Error saving {uploaded_file.name}: {str(e)}")
                        st.error(f"❌ Error saving {uploaded_file.name}: {str(e)}")
                        # Debug info
                        st.write(f"🔧 Debug: Trying to save to: {file_path}")
                        st.write(f"🔧 Debug: User directory: {user_dir}")
                        st.write(f"🔧 Debug: Directory exists: {user_dir.exists()}")
    
    with tab2:
        logger.info("📁 Displaying files tab")
        st.header("Your PDF Files")
        
        if user_dir and user_dir.exists():
            pdf_files = list(user_dir.glob("*.pdf"))
            logger.info(f"📊 Found {len(pdf_files)} PDF files in user directory")
            
            if pdf_files:
                st.write(f"You have {len(pdf_files)} PDF file(s):")
                
                for pdf_file in pdf_files:
                    logger.info(f"📄 Displaying file: {pdf_file.name}")
                    col1, col2, col3 = st.columns([3, 1, 1])
                    
                    with col1:
                        st.write(f"📄 {pdf_file.name}")
                        file_size = pdf_file.stat().st_size / 1024  # KB
                        st.caption(f"Size: {file_size:.1f} KB")
                    
                    with col2:
                        # Download button
                        with open(pdf_file, "rb") as file:
                            btn = st.download_button(
                                label="⬇️ Download",
                                data=file.read(),
                                file_name=pdf_file.name,
                                mime="application/pdf",
                                key=f"download_{pdf_file.name}"
                            )
                        if btn:
                            logger.info(f"📥 User downloaded: {pdf_file.name}")
                    
                    with col3:
                        # Delete button
                        if st.button("🗑️ Delete", key=f"delete_{pdf_file.name}"):
                            logger.info(f"🗑️ User initiated delete for: {pdf_file.name}")
                            try:
                                pdf_file.unlink()
                                logger.info(f"✅ File deleted successfully: {pdf_file.name}")
                                st.success(f"✅ {pdf_file.name} deleted!")
                                st.rerun()
                            except Exception as e:
                                logger.error(f"❌ Error deleting {pdf_file.name}: {str(e)}")
                                st.error(f"❌ Error deleting file: {str(e)}")
                    
                    st.markdown("---")
            else:
                logger.info("📁 No PDF files found in user directory")
                st.info("📁 No PDF files found. Upload some files using the 'Upload PDF' tab.")
        else:
            logger.info("📁 User directory does not exist yet")
            st.info("📁 Your personal folder will be created when you upload your first file.")
    
    with tab3:
        logger.info("📊 Displaying statistics tab")
        st.header("Storage Statistics")
        
        if user_dir and user_dir.exists():
            pdf_files = list(user_dir.glob("*.pdf"))
            total_files = len(pdf_files)
            logger.info(f"📊 Calculating statistics for {total_files} files")
            
            if total_files > 0:
                total_size = sum(f.stat().st_size for f in pdf_files) / (1024 * 1024)  # MB
                logger.info(f"📊 Total storage used: {total_size:.2f} MB")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Total Files", total_files)
                
                with col2:
                    st.metric("Total Size", f"{total_size:.2f} MB")
                
                with col3:
                    avg_size = total_size / total_files
                    st.metric("Average File Size", f"{avg_size:.2f} MB")
                
                # File list with details
                st.subheader("File Details")
                for pdf_file in pdf_files:
                    size_mb = pdf_file.stat().st_size / (1024 * 1024)
                    st.write(f"• {pdf_file.name}: {size_mb:.2f} MB")
            else:
                logger.info("📊 No files for statistics")
                st.info("📊 No statistics available. Upload some files first!")
        else:
            logger.info("📊 No user directory for statistics")
            st.info("📊 No data directory found yet.")

def main():
    """Main application logic"""
    logger.info("🎬 Starting main application logic")
    
    # Handle OAuth callback first
    handle_oauth_callback()
    
    # Check authentication status
    if oauth.is_authenticated():
        logger.info("✅ User is authenticated, showing main app")
        show_main_app()
    else:
        logger.info("🔐 User not authenticated, showing login page")
        show_login_page()

if __name__ == "__main__":
    logger.info("🚀 PDF Manager application started")
    main()