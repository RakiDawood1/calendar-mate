import streamlit as st
from calendar_manager import CalendarManager
from datetime import datetime
from dotenv import load_dotenv
import os
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import json

# Load environment variables for local development
load_dotenv()

def clear_auth_tokens():
    """
    Cleans up all authentication-related session state variables.
    This ensures a clean slate when signing out or when authentication errors occur.
    Also removes any stored credentials for security.
    """
    auth_related_keys = ['authenticated', 'user_info', 'auth_flow']
    for key in auth_related_keys:
        if key in st.session_state:
            del st.session_state[key]
    
    # Clear any stored credentials for security
    for key in list(st.session_state.keys()):
        if key.startswith('credentials_'):
            del st.session_state[key]

def initialize_google_auth():
    """
    Initializes the Google OAuth2 flow with proper scopes and configuration.
    Returns a tuple of (auth_url, state) for the frontend to handle.
    """
    try:
        # Define authentication scopes in required order
        ordered_scopes = [
            'openid',  # OpenID must be first for proper authentication
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        
        # Create client configuration using Streamlit secrets
        client_config = {
            "web": {
                "client_id": st.secrets["google_oauth"]["client_id"],
                "project_id": st.secrets["google_oauth"]["project_id"],
                "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                "token_uri": st.secrets["google_oauth"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["google_oauth"]["client_secret"],
                "redirect_uris": [
                    "https://calendar-mate.streamlit.app/_stcore/oauth2-redirect",
                    "http://localhost:8501/_stcore/oauth2-redirect"
                ]
            }
        }
        
        # Set redirect URI based on environment
        if st.secrets.get("env") == "prod":
            redirect_uri = "https://calendar-mate.streamlit.app/_stcore/oauth2-redirect"
        else:
            redirect_uri = "http://localhost:8501/_stcore/oauth2-redirect"
        
        # Initialize flow with proper configuration
        flow = Flow.from_client_config(
            client_config,
            scopes=ordered_scopes,
            redirect_uri=redirect_uri
        )
        
        # Generate authorization URL with additional parameters
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        return auth_url, state
        
    except Exception as e:
        st.error(f"Authentication initialization error: {str(e)}")
        raise

def render_auth_button():
    """
    Renders the authentication button and handles the OAuth flow initiation
    using a new window approach instead of an iframe.
    """
    if st.button("Sign in with Google", key="google_auth"):
        try:
            auth_url, state = initialize_google_auth()
            
            # Store the state in session for verification later
            st.session_state['oauth_state'] = state
            
            # Create JavaScript to open auth URL in a popup window
            js_code = f"""
                <script>
                    function openGoogleAuth() {{
                        // Open the authorization URL in a popup window
                        const authWindow = window.open(
                            "{auth_url}",
                            "Google Authorization",
                            "width=600,height=600"
                        );
                        
                        // Check if popup was blocked
                        if (authWindow === null) {{
                            alert("Please allow popups for this site to enable Google sign-in.");
                        }}
                    }}
                    
                    // Call the function immediately
                    openGoogleAuth();
                </script>
            """
            
            # Inject the JavaScript code
            st.components.v1.html(js_code, height=0)
            
        except Exception as e:
            st.error(f"Failed to initialize authentication: {str(e)}")
            st.info("Please try again or contact support if the issue persists.")

def get_user_info(credentials):
    """
    Fetches user information using the provided credentials.
    This information is used to personalize the user experience and manage user-specific data.
    """
    from googleapiclient.discovery import build
    
    try:
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        return user_info
    except Exception as e:
        st.error(f"Error fetching user info: {e}")
        return None

def save_credentials(credentials, user_email):
    """
    Securely saves user credentials in Streamlit's session state.
    Uses the user's email as a unique identifier for their credentials.
    """
    try:
        st.session_state[f'credentials_{user_email}'] = credentials.to_json()
    except Exception as e:
        st.error(f"Failed to save credentials: {e}")
        raise

def load_credentials(user_email):
    """
    Loads and validates user credentials from session state.
    Returns None if credentials are not found or invalid.
    """
    try:
        if f'credentials_{user_email}' in st.session_state:
            credentials_json = st.session_state[f'credentials_{user_email}']
            return Credentials.from_authorized_user_info(json.loads(credentials_json))
    except Exception as e:
        st.error(f"Error loading credentials: {e}")
    return None

def validate_auth_state():
    """Enhanced validation of authentication state with detailed error reporting"""
    try:
        if not st.session_state.get('authenticated'):
            st.info("Not authenticated. Please sign in.")
            return False
            
        user_info = st.session_state.get('user_info')
        if not user_info or 'email' not in user_info:
            st.warning("User information is incomplete. Please sign in again.")
            clear_auth_tokens()
            return False
            
        credentials = load_credentials(user_info['email'])
        if not credentials:
            st.warning("No valid credentials found. Please sign in again.")
            clear_auth_tokens()
            return False
            
        if not credentials.valid:
            st.warning("Credentials have expired. Please sign in again.")
            clear_auth_tokens()
            return False
            
        return True
            
    except Exception as e:
        st.error(f"Authentication validation error: {str(e)}")
        st.info("Detailed error information for debugging:")
        st.code(f"""
        Session state keys: {list(st.session_state.keys())}
        Authentication status: {st.session_state.get('authenticated')}
        User info exists: {bool(st.session_state.get('user_info'))}
        """)
        return False

def render_calendar_interface():
    """
    Renders the main calendar interface where users can create events.
    Handles event creation and displays results in a user-friendly format.
    """
    st.write("Enter your meeting or reminder request in natural language. For example:")
    st.write("- 'Schedule a team meeting tomorrow at 2 PM'")
    st.write("- 'Remind me to pay bills next Friday at 10 AM'")
    st.write("- 'Doctor's appointment in 3 days at 2:45 PM'")

    user_input = st.text_input(
        "Enter your request:",
        placeholder="e.g., Schedule a meeting tomorrow at 2pm"
    )

    if st.button("Create Event", use_container_width=True):
        if not user_input:
            st.warning("Please enter an event description.")
            return
            
        try:
            credentials = load_credentials(st.session_state.user_info['email'])
            if not credentials:
                st.error("Authentication error. Please sign in again.")
                clear_auth_tokens()
                st.rerun()
                return

            with st.spinner("Creating your event..."):
                manager = CalendarManager(credentials)
                result = manager.create_event(user_input)
                
            event_details = manager.last_event_details
            if event_details:
                col1, col2 = st.columns(2)
                with col1:
                    st.success("✅ Event created successfully!")
                    st.write("### Event Details")
                    st.write(f"📅 Date: {event_details['date']}")
                    st.write(f"🕒 Time: {event_details['start_time']}")
                    st.write(f"⏱️ Duration: {event_details['duration_minutes']} minutes")
                    st.write(f"📝 Description: {event_details['description']}")
                
                with col2:
                    st.write("### Calendar Link")
                    st.write(result)
            else:
                st.error("Could not create the event. Please try again.")
                st.info("Make sure your request includes a clear date and time.")
        except Exception as e:
            st.error(f"Error creating event: {str(e)}")
            st.info("Please try again or sign out and sign back in if the problem persists.")

def main():
    """
    Main application function that handles the overall flow and user interface.
    Manages authentication state and renders appropriate interfaces based on user state.
    """
    st.title("Calendar Assistant")
    
    # Initialize session state variables if they don't exist
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    
    # Handle query parameters for OAuth callback
    query_params = st.experimental_get_query_params()
    
    # Check if we're handling an OAuth callback
    if 'code' in query_params and 'state' in query_params:
        try:
            # Verify state matches what we stored
            if st.session_state.get('oauth_state') == query_params['state'][0]:
                # Complete the OAuth flow
                flow = initialize_google_auth()[0]  # We only need the flow object here
                flow.fetch_token(code=query_params['code'][0])
                
                # Get user credentials
                credentials = flow.credentials
                
                # Get user info
                user_info = get_user_info(credentials)
                
                if user_info:
                    # Store authentication info
                    st.session_state.authenticated = True
                    st.session_state.user_info = user_info
                    save_credentials(credentials, user_info['email'])
                    
                    # Clear OAuth state
                    if 'oauth_state' in st.session_state:
                        del st.session_state['oauth_state']
                    
                    # Clear query parameters by redirecting
                    st.experimental_set_query_params()
                    st.rerun()
            else:
                st.error("Invalid OAuth state. Please try signing in again.")
                clear_auth_tokens()
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            clear_auth_tokens()
    
    # Validate existing authentication if present
    if st.session_state.authenticated and not validate_auth_state():
        st.warning("Your session has expired. Please sign in again.")
        st.session_state.authenticated = False
    
    # Handle non-authenticated users
    if not st.session_state.authenticated:
        st.write("Please sign in with Google to continue")
        render_auth_button()
    
    # Handle authenticated users
    else:
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.write(f"Welcome, {st.session_state.user_info['name']}!")
        
        with col2:
            if st.button("Sign Out", type="secondary"):
                clear_auth_tokens()
                st.rerun()
        
        render_calendar_interface()

if __name__ == "__main__":
    main()