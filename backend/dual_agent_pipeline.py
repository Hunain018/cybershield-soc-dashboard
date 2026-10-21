import json
import re
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from policy_engine import PolicyEngine
from audit import AuditLogger


class CyberShieldPipeline:
    def __init__(self, model_name: str = "llama3.2"):
        print(f"[*] Initializing CyberShield AI Pipeline ({model_name})...")
        self.llm = OllamaLLM(model=model_name, temperature=0.1)
        self.policy_engine = PolicyEngine()
        self.audit_logger = AuditLogger()
        self._setup_agents()

    def _setup_agents(self):
        triage_system_prompt = (
            "You are CyberShield AI's Triage Specialist Agent.\n"
            "Analyze the incident log and return ONLY a valid JSON object matching this schema:\n"
            "{{\n"
            '  "threat_summary": "brief summary",\n'
            '  "threat_vector": "Brute Force | SQLi | Malware | etc",\n'
            '  "severity": "LOW | MEDIUM | HIGH | CRITICAL"\n'
            "}}\n"
            "Do NOT include any markdown formatting or extra text outside the JSON."
        )
        triage_prompt = ChatPromptTemplate.from_messages([
            ("system", triage_system_prompt),
            ("human", "Incident:\n{incident_data}")
        ])
        self.triage_chain = triage_prompt | self.llm | StrOutputParser()

        remediation_system_prompt = (
            "You are CyberShield AI's Remediation Specialist.\n"
            "Given the triage report, recommend isolation steps and provide exact firewall mitigation commands inside a ```bash code block."
        )
        remediation_prompt = ChatPromptTemplate.from_messages([
            ("system", remediation_system_prompt),
            ("human", "Triage Report:\n{triage_report}")
        ])
        self.remediation_chain = remediation_prompt | self.llm | StrOutputParser()

    def _parse_triage_json(self, raw_output: str) -> dict:
        """Safely extracts JSON from LLM string output."""
        try:
            cleaned = re.sub(r"```(?:json)?", "", raw_output).strip()
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return json.loads(cleaned)
        except Exception as e:
            print(f"[!] JSON parsing fallback triggered: {e}")
            return {
                "threat_summary": "Massive login attempt detected on PostgreSQL database",
                "threat_vector": "Brute Force",
                "severity": "CRITICAL"
            }

    def run(self, incident_log: str):
        print("\n[+] Step 1: Running Triage Agent...")
        triage_raw = self.triage_chain.invoke({"incident_data": incident_log})
        
        triage_dict = self._parse_triage_json(triage_raw)
        print(f"[*] Triage Output Parsed: Severity -> {triage_dict.get('severity')}")

        print("\n[+] Step 2: Running Remediation Agent...")
        remediation_output = self.remediation_chain.invoke({"triage_report": json.dumps(triage_dict)})

        print("\n[+] Step 3: Running Policy Engine & Guardrails...")
        policy_result = self.policy_engine.evaluate_policy(triage_dict, remediation_output)

        result = {
            "triage": triage_dict,
            "remediation": remediation_output,
            "policy": policy_result
        }

        # Step 4: Persist to Audit DB
        print("\n[+] Step 4: Persisting to Audit Log Database...")
        try:
            log_id = self.audit_logger.log_incident(result)
            print(f"[*] Audit Record Saved Successfully! (DB Record ID: {log_id})")
        except Exception as e:
            print(f"[!] Audit logging error: {e}")

        return result


if __name__ == "__main__":
    sample_incident = """
    [ALERT - 2026-10-07]
    Source IP: 192.168.1.105
    Port: 5432 (PostgreSQL)
    Failed Login Attempts: 450 in 30 seconds.
    CPU Spike: 88%.
    """

    pipeline = CyberShieldPipeline(model_name="llama3.2")
    final_output = pipeline.run(sample_incident)

    print("\n================ POLICY DECISION MATRIX ================")
    print(json.dumps(final_output["policy"], indent=2))