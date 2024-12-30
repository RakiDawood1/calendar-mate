import streamlit as st
from calendar_manager import CalendarManager
from datetime import datetime
from dotenv import load_dotenv
import os
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import pickle
from pathlib import Path

# Load environment variables
load_dotenv()

def clear_auth_tokens():
    """
    Cleans up all authentication tokens to ensure a fresh start.
    This helps prevent issues with mismatched or expired tokens.
    """
    # Remove the main token file if it exists
    if os.path.exists('token.pickle'):
        os.remove('token.pickle')
    
    # Clean up any tokens in the tokens directory
    if os.path.exists('tokens'):
        for file in os.listdir('tokens'):
            if file.endswith('.pickle'):
                os.remove(os.path.join('tokens', file))

def initialize_google_auth():
    """
    Initialize Google OAuth2 flow with carefully ordered scopes.
    The order of scopes is important for consistent authentication.
    """
    # Define scopes in the specific order expected by Google's authentication
    ordered_scopes = [
        'openid',  # OpenID must come first
        'https://www.googleapis.com/auth/calendar',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ]
    
    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=ordered_scopes,
        redirect_uri='urn:ietf:wg:oauth:2.0:oob'
    )
    return flow

def get_user_info(credentials):
    """
    Fetch user information using the provided credentials.
    This information is used to personalize the user experience.
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
    Save user credentials securely with their email as identifier.
    This allows multiple users to use the application on the same instance.
    """
    # Create tokens directory if it doesn't exist
    Path("tokens").mkdir(exist_ok=True)
    
    # Save token with user's email as filename for identification
    token_path = f"tokens/{user_email}.pickle"
    with open(token_path, 'wb') as token:
        pickle.dump(credentials, token)

def load_credentials(user_email):
    """
    Load previously saved credentials for a user.
    Returns None if no credentials are found.
    """
    token_path = f"tokens/{user_email}.pickle"
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            return pickle.load(token)
    return None

def main():
    st.title("Calendar Assistant")
    
    # Initialize session state variables for maintaining user state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'auth_flow' not in st.session_state:
        st.session_state.auth_flow = None

    # Handle non-authenticated users
    if not st.session_state.authenticated:
        st.write("Please sign in with Google to continue")
        
        # Show the initial sign-in button
        if st.button("Sign in with Google"):
            flow = initialize_google_auth()
            st.session_state.auth_flow = flow
            
            # Generate and display the authorization URL
            auth_url, _ = flow.authorization_url(prompt='consent')
            
            st.write("Follow these steps to sign in:")
            st.write("1. Click the link below to authorize access")
            st.write("2. Sign in with your Google account")
            st.write("3. Copy the authorization code and paste it below")
            st.markdown(f"[Click here to authorize]({auth_url})")
        
        # Show authorization code input if we have an active auth flow
        if hasattr(st.session_state, 'auth_flow') and st.session_state.auth_flow:
            auth_code = st.text_input(
                "Enter the authorization code:",
                help="After authorizing on Google's website, copy and paste the code here.",
                key="auth_code_input"
            )
            
            # Handle the authorization code submission
            if st.button("Submit Authorization Code") and auth_code:
                try:
                    # Clean up the authorization code
                    auth_code = auth_code.strip()
                    
                    # Exchange the authorization code for credentials
                    st.session_state.auth_flow.fetch_token(code=auth_code)
                    credentials = st.session_state.auth_flow.credentials
                    
                    # Get user information using the credentials
                    user_info = get_user_info(credentials)
                    
                    if user_info:
                        # Store user information and credentials
                        st.session_state.user_info = user_info
                        st.session_state.authenticated = True
                        save_credentials(credentials, user_info['email'])
                        
                        # Clear the auth flow from session state
                        st.session_state.auth_flow = None
                        
                        # Refresh the page to show the authenticated view
                        st.rerun()
                    else:
                        st.error("Could not fetch user information. Please try again.")
                
                except Exception as e:
                    st.error(f"Authentication failed: {str(e)}")
                    st.write("Please make sure you copied the entire authorization code correctly.")
                    st.write("If the error persists, try signing in again.")

    # Handle authenticated users
    else:
        # Create a layout with columns for welcome message and sign out button
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.write(f"Welcome, {st.session_state.user_info['name']}!")
        
        with col2:
            if st.button("Sign Out"):
                clear_auth_tokens()
                st.session_state.authenticated = False
                st.session_state.user_info = None
                st.session_state.auth_flow = None
                st.rerun()
        
        # Display the main calendar interface
        st.write("Enter your meeting or reminder request in natural language. For example:")
        st.write("- 'Schedule a team meeting tomorrow at 2 PM'")
        st.write("- 'Remind me to pay bills next Friday at 10 AM'")
        st.write("- 'Doctor's appointment in 3 days at 2:45 PM'")

        # Event creation interface
        user_input = st.text_input(
            "Enter your request:",
            placeholder="e.g., Schedule a meeting tomorrow at 2pm"
        )

        if st.button("Create Event"):
            if user_input:
                # Load the user's credentials and create the event
                credentials = load_credentials(st.session_state.user_info['email'])
                if credentials:
                    manager = CalendarManager(credentials)
                    result = manager.create_event(user_input)
                    
                    # Display the event details
                    event_details = manager.last_event_details
                    if event_details:
                        st.success(f"""
                        ✅ Event created successfully!
                        
                        📅 Date: {event_details['date']}
                        🕒 Time: {event_details['start_time']}
                        ⏱️ Duration: {event_details['duration_minutes']} minutes
                        📝 Description: {event_details['description']}
                        """)
                        
                        # Show the Google Calendar link
                        st.write(result)
                    else:
                        st.error("Could not create the event. Please try again.")
                else:
                    st.error("Authentication error. Please sign in again.")

if __name__ == "__main__":
    main()