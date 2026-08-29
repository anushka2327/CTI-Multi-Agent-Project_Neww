
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from groq import Groq


# ==========================================
# PROJECT PATH
# ==========================================

sys.path.append(
    str(Path(__file__).resolve().parent.parent)
)


# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()


# ==========================================
# GROQ CLIENT
# ==========================================

llm_client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)


# ==========================================
# THREAT ANALYZER AGENT
# ==========================================

def threat_analyzer_agent(query, retrieved_results):

    """
    Threat Analyzer Agent

    Analyzes information retrieved by the
    Retriever Agent and extracts:

    - Threat Type
    - Malware
    - Attack Summary
    - IOCs
    - Affected Systems
    """


    print("\n==========================================")
    print("THREAT ANALYZER AGENT")
    print("==========================================")


    # ======================================
    # BUILD RETRIEVED CONTEXT
    # ======================================

    context_parts = []

    for result in retrieved_results:

        context_parts.append(
            f"""
Source: {result["source"]}
Page: {result["page"]}

Text:
{result["text"]}
"""
        )


    context = "\n\n".join(context_parts)


    # ======================================
    # PROMPT
    # ======================================

    prompt = f"""
You are a Cyber Threat Intelligence
Threat Analyzer Agent.

Your job is to analyze the retrieved
information and extract structured
threat intelligence.

IMPORTANT RULES:

1. Use ONLY the retrieved context.
2. Do NOT use outside knowledge.
3. Do NOT invent information.
4. If a field cannot be determined from
   the context, write "Not found in
   retrieved context."
5. Keep the analysis concise and factual.

Extract the following:

1. Threat Type
2. Malware
3. Attack Summary
4. IOCs
5. Affected Systems

Retrieved Context:

{context}

User Query:

{query}

Return the result using exactly this format:

Threat Type:
<answer>

Malware:
<answer>

Attack Summary:
<answer>

IOCs:
- <IOC>
- <IOC>

Affected Systems:
- <system>
- <system>
"""


    # ======================================
    # CALL LLM
    # ======================================

    response = llm_client.chat.completions.create(

        model="openai/gpt-oss-20b",

        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],

        temperature=0
    )


    analysis = response.choices[0].message.content


    # ======================================
    # DISPLAY RESULT
    # ======================================

    print("\n==========================================")
    print("THREAT ANALYSIS")
    print("==========================================")

    print(analysis)


    return analysis


# ==========================================
# TEST THREAT ANALYZER
# ==========================================

if __name__ == "__main__":

    from retriever import retriever_agent


    question = input(
        "\nAsk a cybersecurity question: "
    )


    # --------------------------------------
    # STEP 1: RETRIEVE INFORMATION
    # --------------------------------------

    retrieved_results = retriever_agent(
        question
    )


    # --------------------------------------
    # STEP 2: ANALYZE INFORMATION
    # --------------------------------------

    threat_analysis = threat_analyzer_agent(

        question,

        retrieved_results

    )


    print("\n==========================================")
    print("THREAT ANALYZER COMPLETE")
    print("==========================================")

