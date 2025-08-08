#!/usr/bin/env python3

"""
Test script to verify GeminiGenerator authentication logic
"""

import os
import sys

# Add the garak directory to the path
sys.path.insert(0, '/home/abhiraj_getgarak_com/garak')

from garak.generators.gemini import GeminiGenerator

def test_api_key_auth():
    """Test authentication with API key"""
    print("Testing API key authentication...")
    # Save original env var
    original_key = os.environ.get("GOOGLE_API_KEY")
    
    # Set a fake API key for testing
    os.environ["GOOGLE_API_KEY"] = "fake-test-key"
    
    try:
        generator = GeminiGenerator()
        print("API key authentication: SUCCESS")
        print(f"Client type: {type(generator.client)}")
    except Exception as e:
        print(f"API key authentication: FAILED - {e}")
    finally:
        # Restore original env var
        if original_key:
            os.environ["GOOGLE_API_KEY"] = original_key
        else:
            os.environ.pop("GOOGLE_API_KEY", None)


def test_vertexai_auth():
    """Test authentication with Vertex AI configuration"""
    print("\nTesting Vertex AI authentication...")
    # Save original env vars
    original_key = os.environ.get("GOOGLE_API_KEY")
    original_vertexai = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI")
    original_project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    original_location = os.environ.get("GOOGLE_CLOUD_LOCATION")
    
    # Remove API key and set Vertex AI configuration
    if "GOOGLE_API_KEY" in os.environ:
        del os.environ["GOOGLE_API_KEY"]
    
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"
    os.environ["GOOGLE_CLOUD_PROJECT"] = "test-project"
    os.environ["GOOGLE_CLOUD_LOCATION"] = "us-central1"
    
    try:
        generator = GeminiGenerator()
        print("Vertex AI authentication: SUCCESS")
        print(f"Client type: {type(generator.client)}")
    except Exception as e:
        print(f"Vertex AI authentication: FAILED - {e}")
    finally:
        # Restore original env vars
        if original_key:
            os.environ["GOOGLE_API_KEY"] = original_key
        if original_vertexai:
            os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = original_vertexai
        if original_project:
            os.environ["GOOGLE_CLOUD_PROJECT"] = original_project
        if original_location:
            os.environ["GOOGLE_CLOUD_LOCATION"] = original_location


def test_default_auth():
    """Test default authentication (Gemini API without explicit API key)"""
    print("\nTesting default authentication...")
    # Save original env vars
    original_key = os.environ.get("GOOGLE_API_KEY")
    original_vertexai = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI")
    original_project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    
    # Remove all authentication env vars
    if "GOOGLE_API_KEY" in os.environ:
        del os.environ["GOOGLE_API_KEY"]
    if "GOOGLE_GENAI_USE_VERTEXAI" in os.environ:
        del os.environ["GOOGLE_GENAI_USE_VERTEXAI"]
    if "GOOGLE_CLOUD_PROJECT" in os.environ:
        del os.environ["GOOGLE_CLOUD_PROJECT"]
    
    try:
        generator = GeminiGenerator()
        print("Default authentication: SUCCESS")
        print(f"Client type: {type(generator.client)}")
    except Exception as e:
        print(f"Default authentication: FAILED - {e}")
    finally:
        # Restore original env vars
        if original_key:
            os.environ["GOOGLE_API_KEY"] = original_key
        if original_vertexai:
            os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = original_vertexai
        if original_project:
            os.environ["GOOGLE_CLOUD_PROJECT"] = original_project

if __name__ == "__main__":
    test_api_key_auth()
    test_vertexai_auth()
    test_default_auth()
