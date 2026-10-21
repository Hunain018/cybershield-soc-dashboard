from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

class SOCCopilotAgent:
    def __init__(self, model_name: str = "llama3.2"):
        self.llm = OllamaLLM(model=model_name, temperature=0.2)
        
        system_prompt = (
            "You are CyberShield AI's Senior SOC Analyst Assistant.\n"
            "Your job is to answer security questions, analyze log contexts, explain attack vectors, "
            "and provide exact terminal mitigation commands (iptables, ufw, firewalld).\n"
            "Keep your answers concise, practical, and security-focused."
        )
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", "Incident Context (if any):\n{context}\n\nUser Question: {question}")
        ])
        
        self.chain = prompt | self.llm | StrOutputParser()

    def chat(self, question: str, context: str = "No active incident context provided.") -> str:
        try:
            return self.chain.invoke({"question": question, "context": context})
        except Exception as e:
            return f"Error connecting to AI Copilot: {str(e)}"
