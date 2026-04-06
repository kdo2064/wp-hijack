"""Provider-agnostic AI client — OpenAI, Anthropic, Gemini, Ollama."""



from __future__ import annotations



import asyncio



from typing import Any, AsyncIterator











def _build_messages(



    prompt: str,



    system: str,



    history: list[dict[str, str]] | None,



) -> tuple[list[dict], str | None]:



    """
    Assemble the messages list for OpenAI-style APIs and a system string.
    history is a list of {"role": "user"|"assistant", "content": "..."}
    Returns (messages, system_str_for_anthropic).
    """



    messages: list[dict] = []



    if history:



        messages.extend(history)



    messages.append({"role": "user", "content": prompt})



    return messages, system or ""











def _resolve_ai_params(config: dict[str, Any]) -> dict:



    """
    Extract and normalise AI connection params from config.
    Automatically fixes the api_key for Ollama / local endpoints so a
    placeholder key like 'sk-YOUR-KEY-HERE' does not cause 401 errors.
    """



    provider = config.get("provider", "openai").lower()



    api_key  = config.get("api_key", "")



    model    = config.get("model", "gpt-4o")



    max_tok  = int(config.get("max_tokens", 4096))



    temp     = float(config.get("temperature", 0.2))



    base_url = config.get("base_url")



    timeout  = int(config.get("timeout", 60))











    _is_local = base_url and any(h in str(base_url) for h in ("localhost", "127.0.0.1", "0.0.0.0"))



    if provider in ("ollama", "openai-compat") or _is_local:



        if not api_key or api_key.startswith("sk-YOUR") or "YOUR" in api_key.upper():



            api_key = "ollama"







    return dict(



        provider=provider, api_key=api_key, model=model,



        max_tok=max_tok, temp=temp, base_url=base_url, timeout=timeout,



    )













async def ask(



    prompt: str,



    *,



    system: str = "",



    history: list[dict[str, str]] | None = None,



    config: dict[str, Any],



) -> str:



    """
    Send a prompt to whichever AI provider is configured.
    Returns the text response as a string.
    Raises RuntimeError if AI is disabled or key is missing.

    Optional `history` is a list of prior {"role", "content"} turns for multi-turn chat.
    """



    if not config.get("enabled", True):



        raise RuntimeError("AI is disabled in config.json")







    p = _resolve_ai_params(config)



    provider = p["provider"]; api_key = p["api_key"]; model = p["model"]



    max_tok = p["max_tok"]; temp = p["temp"]; base_url = p["base_url"]; timeout = p["timeout"]







    if provider in ("openai", "ollama", "openai-compat"):



        return await _openai_ask(



            prompt=prompt, system=system, history=history,



            api_key=api_key, model=model,



            max_tokens=max_tok, temperature=temp,



            base_url=base_url, timeout=timeout,



        )



    elif provider == "anthropic":



        return await _anthropic_ask(



            prompt=prompt, system=system, history=history,



            api_key=api_key, model=model,



            max_tokens=max_tok, temperature=temp,



            timeout=timeout,



        )



    elif provider in ("gemini", "google"):



        return await _gemini_ask(



            prompt=prompt, system=system, history=history,



            api_key=api_key, model=model,



            max_tokens=max_tok, temperature=temp,



        )



    else:



        raise ValueError(f"Unknown AI provider: {provider!r}")













async def ask_stream(



    prompt: str,



    *,



    system: str = "",



    history: list[dict[str, str]] | None = None,



    config: dict[str, Any],



) -> AsyncIterator[str]:



    """
    Streaming version of ask().  Yields text chunks as they arrive.
    Falls back to a single-chunk non-streaming call for providers that
    don't expose a streaming SDK (Gemini).
    """



    if not config.get("enabled", True):



        raise RuntimeError("AI is disabled in config.json")







    p = _resolve_ai_params(config)



    provider = p["provider"]; api_key = p["api_key"]; model = p["model"]



    max_tok = p["max_tok"]; temp = p["temp"]; base_url = p["base_url"]; timeout = p["timeout"]







    if provider in ("openai", "ollama", "openai-compat"):



        async for chunk in _openai_ask_stream(



            prompt=prompt, system=system, history=history,



            api_key=api_key, model=model,



            max_tokens=max_tok, temperature=temp,



            base_url=base_url, timeout=timeout,



        ):



            yield chunk



    elif provider == "anthropic":



        async for chunk in _anthropic_ask_stream(



            prompt=prompt, system=system, history=history,



            api_key=api_key, model=model,



            max_tokens=max_tok, temperature=temp,



            timeout=timeout,



        ):



            yield chunk



    else:





        text = await ask(prompt, system=system, history=history, config=config)



        yield text













async def _openai_ask(



    prompt: str, system: str,



    api_key: str, model: str,



    max_tokens: int, temperature: float,



    base_url: str | None, timeout: int,



    history: list[dict[str, str]] | None = None,



) -> str:



    import openai



    client_kwargs: dict = {"api_key": api_key, "timeout": timeout}



    if base_url:



        client_kwargs["base_url"] = base_url



    client = openai.AsyncOpenAI(**client_kwargs)



    messages: list[dict] = []



    if system:



        messages.append({"role": "system", "content": system})



    if history:



        messages.extend(history)



    messages.append({"role": "user", "content": prompt})



    resp = await client.chat.completions.create(



        model=model,



        messages=messages,



        max_tokens=max_tokens,



        temperature=temperature,



    )



    return resp.choices[0].message.content or ""











async def _openai_ask_stream(



    prompt: str, system: str,



    api_key: str, model: str,



    max_tokens: int, temperature: float,



    base_url: str | None, timeout: int,



    history: list[dict[str, str]] | None = None,



) -> AsyncIterator[str]:



    import openai



    client_kwargs: dict = {"api_key": api_key, "timeout": timeout}



    if base_url:



        client_kwargs["base_url"] = base_url



    client = openai.AsyncOpenAI(**client_kwargs)



    messages: list[dict] = []



    if system:



        messages.append({"role": "system", "content": system})



    if history:



        messages.extend(history)



    messages.append({"role": "user", "content": prompt})



    stream = await client.chat.completions.create(



        model=model,



        messages=messages,



        max_tokens=max_tokens,



        temperature=temperature,



        stream=True,



    )



    async for chunk in stream:



        if not chunk.choices:                                   



            continue



        delta = chunk.choices[0].delta.content



        if delta:



            yield delta













async def _anthropic_ask(



    prompt: str, system: str,



    api_key: str, model: str,



    max_tokens: int, temperature: float,



    timeout: int,



    history: list[dict[str, str]] | None = None,



) -> str:



    import anthropic



    client = anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout)



    kwargs: dict = {}



    if system:



        kwargs["system"] = system



    messages: list[dict] = []



    if history:



        messages.extend(history)



    messages.append({"role": "user", "content": prompt})



    msg = await client.messages.create(



        model=model,



        max_tokens=max_tokens,



        temperature=temperature,



        messages=messages,



        **kwargs,



    )



    return msg.content[0].text if msg.content else ""











async def _anthropic_ask_stream(



    prompt: str, system: str,



    api_key: str, model: str,



    max_tokens: int, temperature: float,



    timeout: int,



    history: list[dict[str, str]] | None = None,



) -> AsyncIterator[str]:



    import anthropic



    client = anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout)



    kwargs: dict = {}



    if system:



        kwargs["system"] = system



    messages: list[dict] = []



    if history:



        messages.extend(history)



    messages.append({"role": "user", "content": prompt})



    async with client.messages.stream(



        model=model,



        max_tokens=max_tokens,



        temperature=temperature,



        messages=messages,



        **kwargs,



    ) as stream:



        async for text in stream.text_stream:



            yield text













async def _gemini_ask(



    prompt: str, system: str,



    api_key: str, model: str,



    max_tokens: int, temperature: float,



    history: list[dict[str, str]] | None = None,



) -> str:



    import google.generativeai as genai



    genai.configure(api_key=api_key)



    gen_model = genai.GenerativeModel(



        model_name=model,



        system_instruction=system or None,



        generation_config=genai.types.GenerationConfig(



            max_output_tokens=max_tokens,



            temperature=temperature,



        ),



    )





    if history:



        gemini_history = [



            {"role": ("user" if h["role"] == "user" else "model"), "parts": [h["content"]]}



            for h in history



        ]



        chat = gen_model.start_chat(history=gemini_history)



        loop = asyncio.get_event_loop()



        resp = await loop.run_in_executor(None, lambda: chat.send_message(prompt))



    else:



        loop = asyncio.get_event_loop()



        resp = await loop.run_in_executor(None, lambda: gen_model.generate_content(prompt))



    return resp.text or ""



