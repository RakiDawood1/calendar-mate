from event_parser import EventParser
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from googleapiclient.discovery import build
from calendar_auth import CalendarAuth
import streamlit as st

class CalendarManager:
    def __init__(self, credentials):
        """Initialize CalendarManager with provided credentials"""
        self.parser = EventParser()
        self.service = build('calendar', 'v3', credentials=credentials)
        # Use timezone from secrets with a fallback value
        self.timezone = st.secrets.get("config", {}).get("calendar_timezone", "Asia/Kolkata")
        self.last_event_details = None
        self.default_duration = st.secrets.get("config", {}).get("default_meeting_duration", 30)

    def create_event(self, user_input):
        if not user_input:
            return "No input provided"

        event_details = self.parser.parse_request(user_input)
        self.last_event_details = event_details
        if not event_details:
            return "Failed to parse event details"

        # Validate required fields
        required_fields = ['date', 'start_time', 'description']
        if not all(field in event_details for field in required_fields):
            return "Missing required event details"

        event = {
            'summary': event_details['description'],
            'start': {
                'dateTime': f"{event_details['date']}T{event_details['start_time']}:00",
                'timeZone': self.timezone,
            },
            'end': {
                'dateTime': self.calculate_end_time(event_details),
                'timeZone': self.timezone,
            }
        }

        # Only add attendees if the list is not empty
        if event_details.get('attendees'):
            event['attendees'] = [{'email': email} for email in event_details['attendees']]

        try:
            created_event = self.service.events().insert(
                calendarId='primary', 
                body=event,
                sendUpdates='all'  # Notify attendees
            ).execute()
            return f"Event created: {created_event.get('htmlLink')}"
        except Exception as e:
            st.error(f"Error creating event: {str(e)}")
            return f"Error creating event: {str(e)}"

    def calculate_end_time(self, event_details):
        try:
            start_datetime = datetime.fromisoformat(
                f"{event_details['date']}T{event_details['start_time']}:00"
            )
            # Use duration from event details or fall back to default
            duration = event_details.get('duration_minutes', self.default_duration)
            end_datetime = start_datetime + timedelta(minutes=duration)
            return end_datetime.isoformat()
        except Exception as e:
            st.error(f"Error calculating end time: {str(e)}")
            # If there's an error, use the start time we know is valid
            return (start_datetime + timedelta(minutes=self.default_duration)).isoformat()