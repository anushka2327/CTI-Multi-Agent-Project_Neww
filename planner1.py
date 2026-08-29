
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

llm_client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)


def planner_agent(question):

    planner_prompt = f"""
You are the Planner Agent / Orchestrator of a
multi-agent cybersecurity threat analysis system.

Your job is to analyze the user's query and create a
plan for solving it.

You DO NOT answer the question.

You decide:
1. What type of threat is involved.
2. What information is needed.
3. Which agents need to be activated.
4. What each agent needs to retrieve from the RAG knowledge base.
5. The order in which the agents should work.

AVAILABLE AGENTS:

1. Threat Analyzer
   - Analyzes the threat described in the query.
   - Identifies attack behavior, attack vectors,
     malware behavior, indicators and relevant details.

2. MITRE Mapper
   - Maps attacker behavior to MITRE ATT&CK techniques,
     tactics and procedures.

3. Risk Assessment
   - Determines severity, impact, likelihood,
     affected assets and overall risk.

4. Mitigation
   - Identifies defensive measures, detection methods,
     prevention strategies and recommended mitigations.

RULES:

- Activate ONLY the agents required by the query.
- Do NOT automatically activate all agents.
- An agent should only be activated if its output is
  necessary to answer the user's query.
- Determine dependencies between agents.
- If one agent requires information produced by another
  agent, mention that dependency.
- The Retrieval Plan must explain what information each
  activated agent should retrieve from the RAG knowledge base.
- Do NOT perform the actual RAG retrieval.
- Do NOT answer the user's question.
- Return ONLY the analysis plan.
- Keep the plan clear and structured.

USER QUERY:

{question}

Return the plan in exactly this format:

THREAT TYPE:
<identified threat>

INFORMATION NEEDED:
- <information 1>
- <information 2>
- <information 3>

AGENTS TO ACTIVATE:
1. <agent name> — <why it is needed>
2. <agent name> — <why it is needed>

RETRIEVAL PLAN:

STEP 1:
Agent: <agent name>
Retrieve: <what information should be retrieved>
Search query: <RAG search query>
Purpose: <why this information is needed>

STEP 2:
Agent: <agent name>
Retrieve: <what information should be retrieved>
Search query: <RAG search query>
Purpose: <why this information is needed>

DEPENDENCIES:
- <describe which agent depends on another, if applicable>
"""

    response = llm_client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[
            {
                "role": "user",
                "content": planner_prompt
            }
        ],
        temperature=0
    )

    return response.choices[0].message.content.strip()


if __name__ == "__main__":

    question = input("Ask a question: ")

    plan = planner_agent(question)

    print("\n========== PLANNER OUTPUT ==========\n")
    print(plan)

