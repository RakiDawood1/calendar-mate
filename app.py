import streamlit as st
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import json
from datetime import datetime
from calendar_manager import CalendarManager
from event_parser import EventParser
from dotenv import load_dotenv
from google.auth.transport.requests import Request
from calendar_auth import CalendarAuth

load_dotenv()

def get_user_info(credentials):
    try:
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        return user_info
    except Exception as e:
        st.error(f"Error fetching user info: {str(e)}")
        return None

def handle_auth_callback():
    params = st.query_params
    if 'code' not in params or 'state' not in params:
        return False
        
    if 'oauth_state' not in st.session_state or params['state'] != st.session_state['oauth_state']:
        st.error("Invalid OAuth state")
        return False
        
    try:
        flow = CalendarAuth.create_flow()
        if not flow:
            return False
            
        flow.fetch_token(code=params['code'])
        credentials = flow.credentials
        
        user_info = get_user_info(credentials)
        if not user_info:
            return False
            
        st.session_state.authenticated = True
        st.session_state.user_info = user_info
        CalendarAuth.save_credentials(credentials, user_info['email'])
        
        st.query_params.clear()
        return True
        
    except Exception as e:
        st.error(f"Authentication failed: {str(e)}")
        return False

def render_calendar_interface():
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
            if not st.session_state.user_info:
                st.error("User information not found. Please sign in again.")
                return
                
            credentials = Credentials.from_authorized_user_info(
                json.loads(st.session_state[f'credentials_{st.session_state.user_info["email"]}'])
            )
            
            if not credentials:
                st.error("Authentication error. Please sign in again.")
                clear_auth_tokens()
                st.rerun()
                return

            auth = CalendarAuth()
            if credentials.expired:
                if not auth.refresh_token_if_expired():
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

def clear_auth_tokens():
    auth_related_keys = [
        'authenticated', 
        'user_info', 
        'oauth_state', 
        'oauth_config',
        'last_processed_code'
    ]
    for key in auth_related_keys:
        if key in st.session_state:
            del st.session_state[key]

def render_sign_in_interface():
    st.title("Calendar Assistant - Sign In")
    if st.button("Sign in with Google", use_container_width=True):
        try:
            flow = CalendarAuth.create_flow()
            if not flow:
                return
                
            authorization_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'
            )
            
            st.session_state['oauth_state'] = state
            st.link_button("Continue to Google Sign In", authorization_url)
        except Exception as e:
            st.error(f"Failed to initialize authentication: {str(e)}")

def render_authenticated_interface(user_info):
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Calendar Assistant")
        st.write(f"Welcome, {user_info['name']}!")
    with col2:
        if st.button("Sign Out", use_container_width=True):
            clear_auth_tokens()
            st.rerun()
    
    render_calendar_interface()

def main():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None

    auth = CalendarAuth()
    
    # Handle OAuth callback
    if 'code' in st.query_params and not st.session_state.authenticated:
        if handle_auth_callback():
            st.rerun()
    
    # Check existing credentials
    credentials = auth.get_credentials()
    if credentials:
        st.session_state.authenticated = True
        if 'user_info' not in st.session_state:
            user_info = get_user_info(credentials)
            if user_info:
                st.session_state.user_info = user_info
    
    if not st.session_state.authenticated:
        render_sign_in_interface()
    else:
        render_authenticated_interface(st.session_state.user_info)

if __name__ == "__main__":
    main()