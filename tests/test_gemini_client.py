import os
import sys
import pytest
from unittest.mock import patch, MagicMock

from scanner.llm.gemini_client import GeminiLLMClient

@patch.dict(os.environ, {}, clear=True)
def test_gemini_client_missing_key():
    with pytest.raises(SystemExit) as exc_info:
        GeminiLLMClient()
    assert exc_info.value.code == 1

@patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"})
@patch("google.genai.Client")
def test_gemini_client_success(mock_client_class):
    mock_instance = MagicMock()
    mock_client_class.return_value = mock_instance
    
    mock_response = MagicMock()
    mock_response.text = '{"purpose": "Digital Signature"}'
    mock_instance.models.generate_content.return_value = mock_response
    
    client = GeminiLLMClient()
    assert client.api_key == "test-key"
    
    response = client.analyze("sys", "user")
    assert response == '{"purpose": "Digital Signature"}'

@patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"})
@patch("google.genai.Client")
def test_gemini_client_exception(mock_client_class):
    mock_instance = MagicMock()
    mock_client_class.return_value = mock_instance
    
    mock_instance.models.generate_content.side_effect = Exception("Network Error")
    
    client = GeminiLLMClient()
    response = client.analyze("sys", "user")
    assert response == "" # Falls back gracefully
