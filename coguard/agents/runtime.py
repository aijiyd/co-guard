from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict
from urllib import error, request


class BaseLocalAgentRuntime:
    """Shared execution runtime for local multi-agent requests."""

    def invoke_json(
        self,
        *,
        agent_name: str,
        system_prompt: str,
        user_prompt: str,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> Dict[str, object]:
        text = self.invoke_text(
            agent_name=agent_name,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return _extract_json_payload(text)

    def invoke_text(
        self,
        *,
        agent_name: str,
        system_prompt: str,
        user_prompt: str,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> str:
        raise NotImplementedError


class OpenAICompatibleLocalRuntime(BaseLocalAgentRuntime):
    """Runtime that talks to a local OpenAI-compatible model server."""

    def __init__(
        self,
        base_url: str,
        default_model: str = "",
        api_key: str = "",
        timeout_seconds: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def invoke_text(
        self,
        *,
        agent_name: str,
        system_prompt: str,
        user_prompt: str,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> str:
        del agent_name
        payload = {
            "model": model or self.default_model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if not payload["model"]:
            raise ValueError("OpenAI-compatible local runtime requires a model name.")
        req = request.Request(
            "%s/chat/completions" % self.base_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                content = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:  # pragma: no cover - network dependent
            raise RuntimeError("local runtime request failed: %s" % exc) from exc
        return self._extract_message_content(content)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        return headers

    def _extract_message_content(self, payload: Dict[str, object]) -> str:
        choices = payload.get("choices", [])
        if not choices:
            raise RuntimeError("Runtime response does not contain choices.")
        first_choice = choices[0]
        message = first_choice.get("message", {})
        content = message.get("content", "")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
            return "\n".join(parts)
        return str(content)


class TransformersLocalRuntime(BaseLocalAgentRuntime):
    """Runtime that loads a local Hugging Face model directory lazily."""

    def __init__(
        self,
        model_path: str,
        default_model: str = "",
        device: str = "auto",
    ) -> None:
        self.model_path = model_path or "/model"
        self.default_model = default_model
        self.device = device or "auto"
        self._generators: Dict[str, object] = {}
        self._tokenizers: Dict[str, object] = {}

    def invoke_text(
        self,
        *,
        agent_name: str,
        system_prompt: str,
        user_prompt: str,
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> str:
        del agent_name
        resolved_model_dir, generator, tokenizer = self._load_generator(model or self.default_model)
        prompt_text = self._build_prompt_text(
            tokenizer=tokenizer,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        generation_kwargs = {
            "max_new_tokens": max_tokens,
            "return_full_text": False,
        }
        if tokenizer is not None and tokenizer.pad_token_id is not None:
            generation_kwargs["pad_token_id"] = tokenizer.pad_token_id
        if temperature > 0.0:
            generation_kwargs["do_sample"] = True
            generation_kwargs["temperature"] = temperature
        else:
            generation_kwargs["do_sample"] = False
        outputs = generator(prompt_text, **generation_kwargs)
        if not outputs:
            raise RuntimeError("local transformers runtime returned no outputs")
        first_output = outputs[0]
        if isinstance(first_output, dict):
            return str(first_output.get("generated_text") or first_output.get("text") or "")
        return str(first_output)

    def _load_generator(self, model: str):
        model_dir = self._resolve_model_dir(model)
        cache_key = str(model_dir)
        if cache_key in self._generators:
            return cache_key, self._generators[cache_key], self._tokenizers[cache_key]
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
        except Exception as exc:  # pragma: no cover - dependency dependent
            raise ImportError(
                "Missing local runtime dependencies. Install requirements-local-runtime.txt on the server."
            ) from exc

        tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
        model_obj = AutoModelForCausalLM.from_pretrained(
            str(model_dir),
            local_files_only=True,
            torch_dtype="auto",
            device_map=self.device,
        )
        generator = pipeline(
            task="text-generation",
            model=model_obj,
            tokenizer=tokenizer,
        )
        self._generators[cache_key] = generator
        self._tokenizers[cache_key] = tokenizer
        return cache_key, generator, tokenizer

    def _resolve_model_dir(self, model: str) -> Path:
        if model:
            model_path = Path(model)
            if model_path.is_absolute():
                return model_path
            return (Path(self.model_path).expanduser() / model).resolve()
        return Path(self.model_path).expanduser().resolve()

    def _build_prompt_text(self, *, tokenizer, system_prompt: str, user_prompt: str) -> str:
        if tokenizer is not None and hasattr(tokenizer, "apply_chat_template"):
            try:
                return tokenizer.apply_chat_template(
                    [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    tokenize=False,
                    add_generation_prompt=True,
                )
            except Exception:
                pass
        return (
            "<system>\n%s\n</system>\n<user>\n%s\n</user>\n<assistant>\n"
            % (system_prompt, user_prompt)
        )


def build_local_agent_runtime(
    backend: str,
    *,
    base_url: str = "http://127.0.0.1:8000/v1",
    model_path: str = "/model",
    default_model: str = "",
    api_key: str = "",
    device: str = "auto",
    timeout_seconds: float = 60.0,
) -> BaseLocalAgentRuntime:
    normalized_backend = (backend or "").strip().lower()
    if normalized_backend in {"", "disabled", "none"}:
        raise ValueError("local agent runtime backend is disabled")
    if normalized_backend in {"openai_compatible_local", "vllm_server"}:
        return OpenAICompatibleLocalRuntime(
            base_url=base_url,
            default_model=default_model,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
    if normalized_backend in {"transformers_local", "hf_local"}:
        return TransformersLocalRuntime(
            model_path=model_path,
            default_model=default_model,
            device=device,
        )
    raise ValueError("unsupported local agent runtime backend: %s" % backend)


def _extract_json_payload(text: str) -> Dict[str, object]:
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("empty JSON payload")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    fenced_match = re.search(r"```(?:json)?\s*(\{.*\}|\[.*\])\s*```", cleaned, flags=re.DOTALL)
    if fenced_match:
        return json.loads(fenced_match.group(1))

    for start_char, end_char in (("{", "}"), ("[", "]")):
        start = cleaned.find(start_char)
        end = cleaned.rfind(end_char)
        if start != -1 and end != -1 and end > start:
            candidate = cleaned[start : end + 1]
            parsed = json.loads(candidate)
            if isinstance(parsed, list):
                return {"items": parsed}
            return parsed
    raise ValueError("could not extract JSON from runtime output")
