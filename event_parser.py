import google.generativeai as genai
import json
from datetime import datetime, timedelta
import streamlit as st

class EventParser:
    def __init__(self):
        try:
            api_key = st.secrets.get("secrets", {}).get("GOOGLE_AI_KEY")
            if not api_key:
                api_key = st.secrets.get("GOOGLE_AI_KEY")
            if not api_key:
                raise ValueError("GOOGLE_AI_KEY not found in secrets")
                
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-pro')
        except Exception as e:
            st.error(f"Gemini AI initialization error: {e}")
            self.model = None

    def parse_request(self, user_input: str):
        if not user_input or not user_input.strip():
            st.warning("Please provide an event description.")
            return None

        if not hasattr(self, 'model') or not self.model:
            return {
                "date": datetime.now().strftime("%Y-%m-%d"),
                "start_time": datetime.now().strftime("%H:%M"),
                "duration_minutes": 30,
                "description": user_input,
                "attendees": []
            }

        current_date = datetime.now().astimezone()
        prompt = self._create_prompt(user_input, current_date)

        try:
            response = self.model.generate_content(prompt)
            json_str = response.text.strip()
            
            if json_str.startswith("```json"):
                json_str = json_str[7:-3]
            elif json_str.startswith("```"):
                json_str = json_str[3:-3]
            
            json_str = json_str[json_str.find("{"):json_str.rfind("}")+1].strip()
            parsed_data = json.loads(json_str)
            
            if not self._validate_parsed_data(parsed_data):
                return None
                
            return parsed_data

        except Exception as e:
            st.error(f"Error parsing event: {str(e)}")
            print("Raw response:", response.text if 'response' in locals() else "No response")
            return None

    def _create_prompt(self, user_input: str, current_date: datetime) -> str:
        return f'''
        Parse this calendar event request: "{user_input}"
        Current date and time: {current_date.strftime('%Y-%m-%d %H:%M')}

        Return only a valid JSON object with this structure:
        {{
            "date": "YYYY-MM-DD",
            "start_time": "HH:MM",
            "duration_minutes": integer,
            "description": "Clear event description",
            "attendees": ["email1@example.com"]
        }}
        '''

    def _validate_parsed_data(self, data: dict) -> bool:
        required_fields = ['date', 'start_time', 'duration_minutes', 'description', 'attendees']
        if not all(field in data for field in required_fields):
            missing = [field for field in required_fields if field not in data]
            st.warning(f"Missing required fields: {', '.join(missing)}")
            return False
        return True

    def _validate_date_format(self, date_str: str) -> bool:
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
            return True
        except ValueError:
            return False