import streamlit as st
from calendar_manager import CalendarManager
from datetime import datetime

st.title("Calendar Assistant")
st.write("Enter your meeting or reminder request in natural language. For example:")
st.write("- 'Schedule a team meeting tomorrow at 2 PM'")
st.write("- 'Remind me to pay bills next Friday at 10 AM'")
st.write("- 'Doctor's appointment in 3 days at 2:45 PM'")

user_input = st.text_input("Enter your request:", placeholder="e.g., Schedule a meeting tomorrow at 2pm")

if st.button("Create Event"):
    if user_input:
        manager = CalendarManager()
        result = manager.create_event(user_input)
        
        # Get the event details for display
        event_details = manager.last_event_details  # We'll need to add this
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