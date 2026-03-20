

"""
Este archivo define cómo se comporta el modelo de lenguaje para analizar los logs y generar un informe estructurado. 
Utiliza el modelo LLaMA 3.1 de Ollama para procesar la información y extraer detalles relevantes sobre la severidad,
categoría, observaciones, acciones recomendadas y técnicas MITRE asociadas.
"""
import ollama
import json
import re
import os
from app.prompts import SYSTEM_PROMPT, build_user_prompt

MODEL = "llama3.2:3b"

def get_client():
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    return ollama.Client(host=host)

def analyze_log(log_input: str) -> dict:
    client = get_client()

    response = client.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": build_user_prompt(log_input)},
        ]
    )

    raw = response["message"]["content"].strip()

    try:
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        chunk = raw[start:end]

        if chunk.count("{") > chunk.count("}"):
            chunk += "}"

        return json.loads(chunk)

    except json.JSONDecodeError:
        severity    = re.search(r'"severity"\s*:\s*"(\w+)"', raw)
        category    = re.search(r'"category"\s*:\s*"([^"]+)"', raw)
        observation = re.search(r'"observation"\s*:\s*"([^"]+)"', raw)
        mitre       = re.search(r'"mitre_technique"\s*:\s*"([^"]+)"', raw)
        actions     = re.findall(r'"([^"]{10,})"', raw)

        return {
            "severity":        severity.group(1)    if severity    else "UNKNOWN",
            "category":        category.group(1)    if category    else "Parse Error",
            "observation":     observation.group(1) if observation else raw[:300],
            "actions":         actions[3:6]         if len(actions) > 3 else ["Review manually"],
            "mitre_technique": mitre.group(1)       if mitre       else "N/A"
        }