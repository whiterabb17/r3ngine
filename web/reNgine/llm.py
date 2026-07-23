import openai
import re
import logging
import requests

_logger = logging.getLogger(__name__)

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
    OLLAMA, OPENAI, ANTHROPIC, GEMINI
)
from langchain_community.llms import Ollama
from dashboard.models import LLMConfig
from reNgine.privacy import PIIGate

class LLMBaseGenerator:
    def __init__(self, logger):
        self.logger = logger
        self.gate = PIIGate()
        self.config = LLMConfig.objects.filter(is_active=True).first()
        if not self.config:
            self.logger.warning("No active LLM configuration found. Defaulting to Ollama/llama3.")
            # Fallback or create a dummy config if needed
            self.model_name = 'llama3'
            self.provider = OLLAMA
            self.api_key = None
        else:
            self.model_name = self.config.selected_model
            self.provider = self.config.provider
            self.api_key = self.config.api_key

    def _call_llm(self, system_message, user_message, max_tokens=None):
        """Unified method to call the configured LLM provider with PII protection.

        Args:
            system_message (str): System prompt context for the LLM.
            user_message (str): User query/input prompt.
            max_tokens (int, optional): Maximum token limit for output generation.
        """
        # Anonymize inputs
        masked_system = self.gate.anonymize(system_message)
        masked_user = self.gate.anonymize(user_message)
        
        response = ""
        if self.provider == OLLAMA:
            response = self._call_ollama(masked_system, masked_user)
        elif self.provider == OPENAI:
            response = self._call_openai(masked_system, masked_user, max_tokens=max_tokens)
        elif self.provider == ANTHROPIC:
            response = self._call_anthropic(masked_system, masked_user)
        elif self.provider == GEMINI:
            response = self._call_gemini(masked_system, masked_user)
        else:
            return "Error: Unsupported LLM Provider"
            
        # Deanonymize response
        return self.gate.deanonymize(response)

    def _call_ollama(self, system_message, user_message):
        try:
            prompt = system_message + "\nUser: " + user_message
            prompt = re.sub(r'\t', '', prompt)
            llm = Ollama(base_url=OLLAMA_INSTANCE, model=self.model_name)
            return llm.invoke(prompt)
        except Exception as e:
            self.logger.error(f"Ollama Error: {str(e)}")
            return f"Error: {str(e)}"

    def _call_openai(self, system_message, user_message, max_tokens=None):
        """Execute chat completion request to OpenAI API.

        Handles model parameter compatibility by automatically falling back from
        'max_tokens' to 'max_completion_tokens' if the target model returns HTTP 400
        indicating 'max_tokens' is unsupported.

        Args:
            system_message (str): System prompt for instruction context.
            user_message (str): Input prompt for LLM response generation.
            max_tokens (int, optional): Maximum token generation limit.

        Returns:
            str: Generated text response or error string.
        """
        if not self.api_key:
            return "Error: OpenAI API Key not set"
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ]
            }
            if max_tokens is not None:
                data["max_tokens"] = max_tokens

            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=60
            )

            # Fallback to max_completion_tokens if OpenAI model rejects max_tokens parameter
            if response.status_code == 400 and ("max_tokens" in response.text and "max_completion_tokens" in response.text):
                self.logger.warning(
                    f"OpenAI model '{self.model_name}' rejected 'max_tokens'. Retrying with 'max_completion_tokens'."
                )
                if "max_tokens" in data:
                    token_val = data.pop("max_tokens")
                    data["max_completion_tokens"] = token_val
                response = requests.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=60
                )

            response.raise_for_status()
            return response.json()['choices'][0]['message']['content']
        except Exception as e:
            self.logger.error(f"OpenAI Error: {str(e)}")
            return f"Error: {str(e)}"

    def _call_anthropic(self, system_message, user_message):
        if not self.api_key:
            return "Error: Anthropic API Key not set"
        try:
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            data = {
                "model": self.model_name,
                "max_tokens": 1024,
                "system": system_message,
                "messages": [{"role": "user", "content": user_message}]
            }
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=data,
                timeout=60
            )
            response.raise_for_status()
            block = response.json()['content'][0]
            if block.get('type') != 'text':
                raise ValueError(f"Unexpected Anthropic response content type: {block.get('type')}")
            return block['text']
        except Exception as e:
            self.logger.error(f"Anthropic Error: {str(e)}")
            return f"Error: {str(e)}"

    def _call_gemini(self, system_message, user_message):
        if not self.api_key:
            return "Error: Gemini API Key not set"
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
            headers = {
                "x-goog-api-key": self.api_key,
                "Content-Type": "application/json"
            }
            data = {
                "contents": [{
                    "parts": [{"text": f"{system_message}\n\n{user_message}"}]
                }]
            }
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            return response.json()['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            self.logger.error(f"Gemini Error: {str(e)}")
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