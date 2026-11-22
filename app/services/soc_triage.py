import http.client
import json
import os


def brief(rule, flows, risk, *, allow_model=True):
    count = len(flows)
    soc = (
        f"{count} frames match the {rule['short']} signature. "
        f"Start with frame {flows[0]['frame']} and correlate the network evidence with host logs."
        if count else "No frames matched this rule in the capture."
    )
    executive = (
        f"{len(risk['controls'])} mapped controls need review. The scenario risk score rose "
        f"from {risk['baseline']:g} to {risk['score']:g} out of 25. {rule['review']}"
        if count else "This capture supplied no adverse evidence for this rule."
    )
    fallback = {"source": "Rule-based", "soc": soc, "grc": executive}
    if not count or not allow_model or os.getenv("ENABLE_OLLAMA") != "1":
        return fallback

    # Only derived numbers and reviewed rule metadata leave the analysis service.
    prompt = (
        "Summarise this simulated incident in JSON with string fields soc and grc. "
        "Describe uncertainty. Do not issue commands or make legal determinations. "
        f"Rule: {rule['name']}. Technique: {rule['technique']}. "
        f"Matching frames: {count}. Scenario risk: {risk['score']}/25."
    )
    client = http.client.HTTPConnection("127.0.0.1", 11434, timeout=5)
    try:
        body = json.dumps({"model": "llama3.1:8b", "prompt": prompt, "stream": False,
                           "format": "json", "options": {"num_predict": 180}})
        client.request("POST", "/api/generate", body, {"Content-Type": "application/json"})
        response = client.getresponse()
        if response.status == 200:
            answer = json.loads(json.loads(response.read(32_768))["response"])
            if isinstance(answer, dict) and all(isinstance(answer.get(key), str)
                    and 0 < len(answer[key].strip()) <= 1500 for key in ("soc", "grc")):
                return {"source": "Local Ollama", "soc": answer["soc"], "grc": answer["grc"]}
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        pass
    finally:
        client.close()
    return fallback
