import os
import sys

class GeminiLLMClient:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            print("Error: GEMINI_API_KEY environment variable is missing. Cannot use Gemini LLM mode.", file=sys.stderr)
            sys.exit(1)
            
        self.model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        
        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except ImportError:
            print("Error: google-genai SDK is not installed. Please run: pip install -r requirements.txt", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            # Handle instantiation exceptions safely
            print(f"Error: Failed to initialize Gemini client.", file=sys.stderr)
            sys.exit(1)

    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        try:
            from google import genai
            
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=user_prompt,
                config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json"
                )
            )
            
            if response and response.text:
                return response.text
            return ""
        except Exception as e:
            # Ensure safe degradation on any provider failure (e.g. network timeout, rate limit, unauthorized)
            # Returning an empty string will trigger the LLMAnalyzer's JSONDecodeError fallback
            return ""
