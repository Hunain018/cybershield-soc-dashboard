import re

class PolicyEngine:
    def __init__(self):
        # Whitelisted safe commands and syntax patterns
        self.allowed_command_patterns = [
            r"^iptables -A INPUT -s \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} -j DROP$",
            r"^iptables -A INPUT -p tcp --dport \d{2,5} -j DROP$",
            r"^ufw deny from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        ]

    def evaluate_policy(self, triage_data: dict, remediation_text: str) -> dict:
        severity = triage_data.get("severity", "LOW").upper()
        threat_vector = triage_data.get("threat_vector", "Unknown")
        
        # Determine Execution Mode based on Risk Matrix
        if severity in ["CRITICAL", "HIGH"]:
            action_status = "AUTO_EXECUTE_APPROVED"
        else:
            action_status = "REQUIRES_HUMAN_APPROVAL"

        # Extract and validate CLI commands from remediation plan
        extracted_commands = self._extract_commands(remediation_text)
        validated_commands = []
        rejected_commands = []

        for cmd in extracted_commands:
            if self._validate_command(cmd):
                validated_commands.append(cmd)
            else:
                rejected_commands.append(cmd)

        return {
            "threat_vector": threat_vector,
            "severity": severity,
            "action_status": action_status,
            "validated_commands": validated_commands,
            "rejected_commands": rejected_commands,
            "policy_passed": len(rejected_commands) == 0 and len(validated_commands) > 0
        }

    def _extract_commands(self, text: str) -> list:
        """Extracts bash code block commands from remediation text."""
        commands = re.findall(r"```bash\n(.*?)\n```", text, re.DOTALL)
        clean_commands = []
        for block in commands:
            for line in block.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("sudo apt"):
                    clean_commands.append(line)
        return clean_commands

    def _validate_command(self, command: str) -> bool:
        """Sanitizes and checks command against security rules."""
        for pattern in self.allowed_command_patterns:
            if re.match(pattern, command):
                return True
        return False