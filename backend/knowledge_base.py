import json
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

KNOWLEDGE_FILE = os.path.join(os.path.dirname(__file__), "knowledge_data.json")

# Rule name se behtar retrieval query banane ke liye expansion mapping.
# TF-IDF exact token match karta hai (no stemming), isliye 'SCAN' aur
# corpus ka 'scanning' alag token hain - ye mapping un gaps ko explicitly
# bharta hai un rules ke liye jo detection.py (Day 3) mein defined hain.
RULE_QUERY_EXPANSION = {
    "BRUTE_FORCE_AUTH_FAILURE": (
        "brute force password guessing credential access repeated failed "
        "authentication login attempts valid accounts"
    ),
    "PORT_SCAN_DETECTED": (
        "port scanning network service discovery reconnaissance active "
        "scanning ports remote host probing"
    ),
}


class KnowledgeBase:
    def __init__(self, knowledge_path=KNOWLEDGE_FILE):
        with open(knowledge_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.documents = []   # har entry: dict with id, kind, text, metadata

        for item in data.get("mitre_attack", []):
            text = f"{item['id']} {item['name']} {item['tactic']} {item['description']}"
            self.documents.append({
                "kind": "mitre_attack",
                "ref_id": item["id"],
                "title": item["name"],
                "text": text,
                "raw": item,
            })

        for item in data.get("cves", []):
            text = f"{item['id']} {item['product']} {item['severity']} {item['description']}"
            self.documents.append({
                "kind": "cve",
                "ref_id": item["id"],
                "title": item["product"],
                "text": text,
                "raw": item,
            })

        corpus_texts = [d["text"] for d in self.documents]
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.tfidf_matrix = self.vectorizer.fit_transform(corpus_texts)

    def retrieve(self, query, top_k=5, min_score=0.05):
        """
        Query ke liye top-k relevant documents return karta hai, har ek
        source reference ke saath - taake agent 'citation' de sake, generic
        text nahi.
        """
        query_vec = self.vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self.tfidf_matrix).flatten()

        ranked_idx = scores.argsort()[::-1][:top_k]

        results = []
        for idx in ranked_idx:
            score = float(scores[idx])
            if score < min_score:
                continue
            doc = self.documents[idx]
            results.append({
                "kind": doc["kind"],
                "reference": doc["ref_id"],
                "title": doc["title"],
                "score": round(score, 4),
                "excerpt": doc["raw"].get("description", ""),
                "source": "MITRE ATT&CK" if doc["kind"] == "mitre_attack" else "NVD CVE",
            })
        return results

    def retrieve_for_incident(self, rule_names, event_type=None, top_k=5):
        """
        Incident ke rule names se ek retrieval query banata hai.
        Known rules ke liye expanded query use karta hai (behtar recall),
        naye/unknown rules ke liye raw text fallback karta hai.
        Agent.py isko directly use karega.
        """
        query_parts = []

        if rule_names:
            for single_rule in rule_names.split(","):
                single_rule = single_rule.strip()
                if single_rule in RULE_QUERY_EXPANSION:
                    query_parts.append(RULE_QUERY_EXPANSION[single_rule])
                else:
                    query_parts.append(single_rule.replace("_", " "))

        if event_type:
            query_parts.append(event_type.replace("_", " "))

        query = " ".join(query_parts) if query_parts else "network intrusion anomaly"
        return self.retrieve(query, top_k=top_k)


def main():
    kb = KnowledgeBase()
    print(f"Knowledge base load ho gaya: {len(kb.documents)} documents "
          f"({sum(1 for d in kb.documents if d['kind']=='mitre_attack')} MITRE techniques, "
          f"{sum(1 for d in kb.documents if d['kind']=='cve')} CVEs)\n")

    test_queries = [
        ("BRUTE_FORCE_AUTH_FAILURE (expanded)", RULE_QUERY_EXPANSION["BRUTE_FORCE_AUTH_FAILURE"]),
        ("PORT_SCAN_DETECTED (expanded)", RULE_QUERY_EXPANSION["PORT_SCAN_DETECTED"]),
        ("credential theft phishing", "credential theft phishing"),
    ]

    for label, q in test_queries:
        print(f"Query: '{label}'")
        results = kb.retrieve(q, top_k=3)
        if not results:
            print("  (koi relevant result nahi mila)")
        for r in results:
            print(f"  [{r['source']}] {r['reference']} - {r['title']} "
                  f"(score={r['score']})")
        print()


if __name__ == "__main__":
    main()
