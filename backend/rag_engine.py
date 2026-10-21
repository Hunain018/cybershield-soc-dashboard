import chromadb
from chromadb.utils import embedding_functions

class ThreatIntelRAG:
    def __init__(self):
        self.client = chromadb.Client()
        self.ef = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_or_create_collection(
            name="mitre_threat_intel",
            embedding_function=self.ef
        )
        self._seed_data()

    def _seed_data(self):
        # Indexing MITRE ATT&CK Techniques & Policies
        if self.collection.count() == 0:
            self.collection.add(
                documents=[
                    "T1110: SSH Brute Force Attack. Mitigation: Block source IP via iptables/UFW and enforce SSH keys.",
                    "T1190: SQL Injection targeting Web Application endpoints. Mitigation: Use parameterized queries and block IP on WAF.",
                    "T1046: Network Service Discovery / Port Scanning. Mitigation: Block scanning subnet and alert SOC Tier-2."
                ],
                metadatas=[
                    {"technique": "T1110", "severity": "HIGH"},
                    {"technique": "T1190", "severity": "CRITICAL"},
                    {"technique": "T1046", "severity": "MEDIUM"}
                ],
                ids=["mitre_t1110", "mitre_t1190", "mitre_t1046"]
            )

    def query(self, threat_query: str) -> str:
        results = self.collection.query(query_texts=[threat_query], n_results=1)
        if results and results['documents'][0]:
            return results['documents'][0][0]
        return "No specific RAG threat intel matched."