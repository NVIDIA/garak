"""Test for issue #1919 fix - OWASP tag consistency"""
import pytest
from garak.detectors.agent_breaker import AgentBreakerResult


def test_agent_breaker_owasp_tags():
    """Test that AgentBreaker uses correct OWASP 2025 tags"""
    detector = AgentBreakerResult()
    
    # Verify owasp:llm06 is present (2025 version for Excessive Agency)
    assert "owasp:llm06" in detector.tags, "AgentBreaker should be tagged with owasp:llm06 (Excessive Agency)"
    
    # Verify old 2023-2024 tags are not present
    assert "owasp:llm07" not in detector.tags, "AgentBreaker should not use owasp:llm07 (2023 version)"
    assert "owasp:llm08" not in detector.tags, "AgentBreaker should not use owasp:llm08 (2023 version)"
    
    # Verify other expected tags are present
    assert "owasp:llm01" in detector.tags, "AgentBreaker should retain owasp:llm01 for prompt injection"
    assert "quality:Security:AgentSecurity" in detector.tags
    assert "payload:agentic:exploitation" in detector.tags


def test_agent_breaker_doc_uri_alignment():
    """Test that doc_uri aligns with OWASP tags"""
    detector = AgentBreakerResult()
    
    # doc_uri should point to LLM06 (Excessive Agency)
    assert "llm06" in detector.doc_uri.lower(), "doc_uri should reference LLM06"
    assert "excessive-agency" in detector.doc_uri.lower(), "doc_uri should reference Excessive Agency"
    
    # Tags should be consistent with doc_uri
    assert "owasp:llm06" in detector.tags, "Tags should match doc_uri classification"


if __name__ == "__main__":
    test_agent_breaker_owasp_tags()
    test_agent_breaker_doc_uri_alignment()
    print("All tests passed!")
