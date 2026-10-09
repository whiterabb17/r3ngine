import os
import re
import logging

_logger = logging.getLogger(__name__)

# Master switch for every LLM call. Operators toggle this in Settings → AI Hub.
# Off by default: with no active LLMConfig the generators used to fall back to
# Ollama, but no `ollama` service exists in docker/docker-compose.yml, so each
# call burned its retry budget on "Failed to resolve 'ollama'".
LLM_DISABLED_MESSAGE = (
    "Error: LLM features are disabled "
    "(enable LLM in Settings → AI Hub and activate a provider)"
)


def llm_enabled():
    """True when the operator has enabled LLM features in Settings → AI Hub."""
    from dashboard.models import LLMSettings
    return bool(LLMSettings.get_solo().enabled)


llm_env_enabled = llm_enabled

_PROMPT_INJECTION_RE = re.compile(
    r'(ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)|'
    r'forget\s+(your|the|all)\s+(instructions?|prompts?|context)|'
    r'disregard\s+(previous|all|above)\s+(instructions?|prompts?)|'
    r'<\|im_start\|>|<\|endoftext\|>|<\|im_sep\|>|'
    r'\[SYSTEM\]|\[INST\])',
    re.IGNORECASE,
)
_MAX_PROMPT_INPUT_LENGTH = 8000


def _sanitize_for_prompt(text: str) -> str:
    """Truncate and check for prompt injection patterns before sending to an LLM.

    Raises ValueError if injection patterns are detected.
    """
    if not text:
        return text
    truncated = text[:_MAX_PROMPT_INPUT_LENGTH]
    if _PROMPT_INJECTION_RE.search(truncated):
        _logger.warning('Potential prompt injection attempt detected in LLM input')
        raise ValueError('Input contains disallowed content for LLM processing')
    return truncated
from reNgine.common_func import parse_llm_vulnerability_report
from reNgine.definitions import (
    VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE, 
    ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT, 
    OLLAMA_INSTANCE,
    OLLAMA, OPENAI, OPENAI_COMPATIBLE, ANTHROPIC, GEMINI
)
from langchain_community.llms import Ollama
from dashboard.models import LLMConfig
from reNgine import llm_client
from reNgine.privacy import PIIGate

NO_QUESTIONS_SYSTEM_SUFFIX = (
    "\n\nCRITICAL SYSTEM REQUIREMENT FOR ALL GENERATIONS: "
    "Do NOT include any conversational follow-up questions, closing queries, "
    "or offers for further assistance (such as 'Would you like to include a longer brief?', "
    "'Let me know if you need more details', or 'Should I expand on this?'). "
    "Output ONLY the requested report content or structured response directly."
)

class LLMBaseGenerator:
    def __init__(self, logger):
        self.logger = logger
        self.gate = PIIGate()
        self.config = LLMConfig.objects.filter(is_active=True).first()
        if not self.config:
            # Deliberately no Ollama fallback here — see LLM_DISABLED_MESSAGE.
            self.model_name = None
            self.provider = None
            self.api_key = None
            self.base_url = None
        else:
            self.model_name = self.config.selected_model
            self.provider = self.config.provider
            self.api_key = self.config.api_key
            self.base_url = self.config.base_url
        settings_on = llm_enabled()
        self.enabled = settings_on and self.config is not None
        if not self.enabled:
            self.logger.info(
                "LLM features disabled (settings enabled=%s, active config=%s)",
                settings_on, bool(self.config),
            )

    def _call_llm(self, system_message, user_message, max_tokens=None):
        """Unified method to call the configured LLM provider with PII protection.

        Args:
            system_message (str): System prompt context for the LLM.
            user_message (str): User query/input prompt.
            max_tokens (int, optional): Maximum token limit for output generation.
        """
        if not self.enabled:
            return LLM_DISABLED_MESSAGE

        # Ensure universal requirement against conversational follow-ups/questions is present
        if "CRITICAL SYSTEM REQUIREMENT FOR ALL GENERATIONS" not in system_message:
            system_message = f"{system_message}{NO_QUESTIONS_SYSTEM_SUFFIX}"

        # Anonymize inputs
        masked_system = self.gate.anonymize(system_message)
        masked_user = self.gate.anonymize(user_message)
        
        response = ""
        if self.provider == OLLAMA:
            response = self._call_ollama(masked_system, masked_user)
        elif self.provider == OPENAI:
            response = self._call_openai(masked_system, masked_user, max_tokens=max_tokens)
        elif self.provider == OPENAI_COMPATIBLE:
            response = self._call_openai_compatible(masked_system, masked_user, max_tokens=max_tokens)
        elif self.provider == ANTHROPIC:
            response = self._call_anthropic(masked_system, masked_user, max_tokens=max_tokens)
        elif self.provider == GEMINI:
            response = self._call_gemini(masked_system, masked_user, max_tokens=max_tokens)
        else:
            return "Error: Unsupported LLM Provider"
            
        # Deanonymize response
        return self.gate.deanonymize(response)

    def _call_ollama(self, system_message, user_message):
        try:
            prompt = system_message + "\nUser: " + user_message
            prompt = re.sub(r'\t', '', prompt)
            llm = Ollama(base_url=OLLAMA_INSTANCE, model=self.model_name, timeout=120)
            return llm.invoke(prompt)
        except Exception as e:
            self.logger.error("Ollama Error: %s", str(e))
            return f"Error: {str(e)}"

    def _call_openai(self, system_message, user_message, max_tokens=None):
        return self._call_cloud(OPENAI, 'OpenAI', system_message, user_message, max_tokens)

    def _call_openai_compatible(self, system_message, user_message, max_tokens=None):
        if not self.base_url:
            return "Error: OpenAI-compatible base URL not set"
        return self._call_cloud(OPENAI_COMPATIBLE, 'OpenAI-compatible', system_message, user_message, max_tokens)

    def _call_anthropic(self, system_message, user_message, max_tokens=None):
        return self._call_cloud(ANTHROPIC, 'Anthropic', system_message, user_message, max_tokens)

    def _call_gemini(self, system_message, user_message, max_tokens=None):
        return self._call_cloud(GEMINI, 'Gemini', system_message, user_message, max_tokens)

    def _call_cloud(self, provider, label, system_message, user_message, max_tokens=None):
        """One request through reNgine.llm_client; failures come back as an "Error: ..." string."""
        if not self.api_key:
            return f"Error: {label} API Key not set"
        try:
            return llm_client.complete(
                provider,
                api_key=self.api_key,
                model=self.model_name,
                system=system_message,
                user=user_message,
                max_tokens=max_tokens,
                base_url=self.base_url,
            )
        except Exception as e:
            self.logger.error("%s Error: %s", label, str(e))
            return f"Error: {str(e)}"

class LLMVulnerabilityReportGenerator(LLMBaseGenerator):
    def get_vulnerability_description(self, description):
        self.logger.info("Generating Vulnerability Description")
        try:
            description = _sanitize_for_prompt(description)
        except ValueError as e:
            return {'status': False, 'error': str(e)}
        response_content = self._call_llm(VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE, description)
        
        if response_content.startswith("Error:"):
            return {'status': False, 'error': response_content}

        response = parse_llm_vulnerability_report(response_content)
        if not response:
            return {'status': False, 'error': 'Failed to parse LLM response'}

        return {
            'status': True,
            'description': response.get('description', ''),
            'impact': response.get('impact', ''),
            'remediation': response.get('remediation', ''),
            'references': response.get('references', []),
        }

class LLMAttackSuggestionGenerator(LLMBaseGenerator):
    def get_attack_suggestion(self, user_input):
        self.logger.info("Generating Attack Suggestion")
        try:
            user_input = _sanitize_for_prompt(user_input)
        except ValueError as e:
            return {'status': False, 'error': str(e), 'input': ''}
        response_content = self._call_llm(ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT, user_input)
        
        if response_content.startswith("Error:"):
            return {'status': False, 'error': response_content, 'input': user_input}
            
        return {
            'status': True,
            'description': response_content,
            'input': user_input
        }

class LLMReportGenerator(LLMBaseGenerator):
    def _generate_section(self, system_prompt, context):
        return self._call_llm(system_prompt, context)

    def generate_overview(self, context):
        from reNgine.definitions import LLM_REPORT_OVERVIEW_SYSTEM_PROMPT
        return self._generate_section(LLM_REPORT_OVERVIEW_SYSTEM_PROMPT, context)

    def generate_executive_brief(self, context):
        from reNgine.definitions import LLM_REPORT_EXECUTIVE_BRIEF_SYSTEM_PROMPT
        return self._generate_section(LLM_REPORT_EXECUTIVE_BRIEF_SYSTEM_PROMPT, context)

    def generate_conclusion(self, context):
        from reNgine.definitions import LLM_REPORT_CONCLUSION_SYSTEM_PROMPT
        return self._generate_section(LLM_REPORT_CONCLUSION_SYSTEM_PROMPT, context)

    def generate_attack_scenario(self, vulnerability_context):
        from reNgine.definitions import LLM_ATTACK_SCENARIO_SYSTEM_PROMPT
        return self._generate_section(LLM_ATTACK_SCENARIO_SYSTEM_PROMPT, vulnerability_context)

    def generate_path_remediation(self, path_id: str, path_context: str) -> str:
        from reNgine.definitions import LLM_ATTACK_PATH_REMEDIATION_SYSTEM_PROMPT
        return self._generate_section(
            LLM_ATTACK_PATH_REMEDIATION_SYSTEM_PROMPT,
            f"Attack Path ID: {path_id}\n\n{path_context}",
        )


class LLMImpactGenerator(LLMBaseGenerator):
    def generate_impact_assessment(self, vulnerability_context):
        # Fallback system prompt if not defined in definitions.py
        try:
            from reNgine.definitions import LLM_IMPACT_ASSESSMENT_SYSTEM_PROMPT
        except ImportError:
            LLM_IMPACT_ASSESSMENT_SYSTEM_PROMPT = "You are a senior security architect. Given the following attack path and findings, describe the potential business impact and suggest a remediation priority. Focus on real-world risk."
        
        return self._call_llm(LLM_IMPACT_ASSESSMENT_SYSTEM_PROMPT, vulnerability_context)


class LLMAttackPathExplainer(LLMBaseGenerator):
    """Generates an in-depth tactical explanation for a specific attack path.

    Inherits from LLMBaseGenerator to support configured LLM providers and
    automatically apply PII masking/unmasking (IPs, emails, hostnames).
    """

    def explain_path(self, path_id, path_details_str):
        """Request explanation from LLM using standard system prompt and formatted details.

        Args:
            path_id (str): The unique ID identifying the attack path.
            path_details_str (str): A newline-separated string containing step details,
                nodes, confidence levels, and potential impacts.

        Returns:
            str: The LLM-generated tactical explanation with original PII restored.
        """
        system_message = (
            "You are an expert cybersecurity analyst. Provide an in-depth, tactical, "
            "and clear explanation of the following attack path, detailing how each step is executed, "
            "the risks associated with the transitions, and a mitigation recommendation. "
            "Keep the tone professional and focus on real-world impact. Do not include system metadata "
            "or raw JSON structures in your response."
        )
        user_message = f"Attack Path ID: {path_id}\n\nPath Details:\n{path_details_str}"
        return self._call_llm(system_message, user_message)


class LLMSeverityValidator(LLMBaseGenerator):
    """Generates an AI-powered severity assessment and validation for a vulnerability finding."""

    def validate_severity(self, vulnerability_context: str) -> dict:
        import json
        from reNgine.definitions import LLM_VULNERABILITY_SEVERITY_VALIDATION_SYSTEM_PROMPT
        
        try:
            vulnerability_context = _sanitize_for_prompt(vulnerability_context)
        except ValueError as e:
            return {'status': False, 'error': str(e)}

        raw_response = self._call_llm(LLM_VULNERABILITY_SEVERITY_VALIDATION_SYSTEM_PROMPT, vulnerability_context)

        if raw_response.startswith("Error:"):
            return {'status': False, 'error': raw_response}

        # Clean JSON block if model returned markdown code blocks
        clean_json = raw_response.strip()
        if clean_json.startswith("```"):
            clean_json = re.sub(r'^```(?:json)?\n?', '', clean_json)
            clean_json = re.sub(r'\n?```$', '', clean_json)
        clean_json = clean_json.strip()

        try:
            parsed = json.loads(clean_json)
            return {
                'status': True,
                'suggested_severity': str(parsed.get('suggested_severity', 'info')).lower(),
                'suggested_cvss_score': parsed.get('suggested_cvss_score'),
                'confidence': parsed.get('confidence', 'High'),
                'reasoning': parsed.get('reasoning', ''),
                'key_factors': parsed.get('key_factors', []),
                'raw_response': raw_response,
            }
        except Exception as e:
            self.logger.warning("Failed to parse LLM severity validation JSON: %s. Fallback raw string returned.", str(e))
            return {
                'status': True,
                'suggested_severity': 'info',
                'suggested_cvss_score': None,
                'confidence': 'Low',
                'reasoning': raw_response,
                'key_factors': [],
                'raw_response': raw_response,
            }