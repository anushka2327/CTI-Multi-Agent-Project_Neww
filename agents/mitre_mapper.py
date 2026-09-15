import json
import os
import re

from dotenv import load_dotenv
from groq import Groq


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

GROQ_MODEL = "openai/gpt-oss-120b"


# ============================================================
# GROQ CLIENT
# ============================================================

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise RuntimeError(
        "GROQ_API_KEY is not set. "
        "Please configure your Groq API key."
    )

llm_client = Groq(
    api_key=api_key
)


# ============================================================
# MITRE ATT&CK TECHNIQUE KNOWLEDGE BASE
# ============================================================

MITRE_TECHNIQUES = {

    # ---------------- INITIAL ACCESS ----------------

    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "keywords": [
            "phishing attachment",
            "spearphishing attachment",
            "malicious attachment",
            "email attachment",
            "malicious document"
        ]
    },

    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "keywords": [
            "spearphishing link",
            "phishing link",
            "malicious link",
            "phishing url"
        ]
    },

    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "keywords": [
            "phishing",
            "spear phishing",
            "spearphishing"
        ]
    },

    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "keywords": [
            "public-facing application",
            "internet-facing application",
            "exploited public-facing",
            "exploit internet-facing",
            "web application exploit"
        ]
    },


    # ---------------- EXECUTION ----------------

    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "keywords": [
            "powershell",
            "powershell.exe",
            "invoke-command",
            "invoke-expression",
            "iex"
        ]
    },

    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "keywords": [
            "cmd.exe",
            "windows command shell",
            "command shell",
            "cmd /c"
        ]
    },

    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "keywords": [
            "bash",
            "unix shell",
            "/bin/sh",
            "/bin/bash"
        ]
    },

    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": [
            "command execution",
            "command interpreter",
            "scripting interpreter",
            "execute commands"
        ]
    },

    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Execution",
        "keywords": [
            "scheduled task",
            "task scheduler",
            "schtasks",
            "scheduled job"
        ]
    },


    # ---------------- PERSISTENCE ----------------

    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "keywords": [
            "registry run key",
            "run key",
            "startup folder",
            "registry persistence"
        ]
    },


    # ---------------- DEFENSE EVASION ----------------

    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "keywords": [
            "valid accounts",
            "stolen credentials",
            "compromised account",
            "compromised credentials",
            "legitimate credentials"
        ]
    },

    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "keywords": [
            "obfuscated",
            "obfuscation",
            "encoded payload",
            "base64 encoded",
            "encoded command"
        ]
    },

    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "keywords": [
            "process injection",
            "inject into process",
            "code injection",
            "remote thread injection"
        ]
    },

    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "keywords": [
            "disable antivirus",
            "disable security tools",
            "disable defender",
            "disable security software",
            "impair defenses"
        ]
    },


    # ---------------- CREDENTIAL ACCESS ----------------

    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": [
            "credential dumping",
            "credential dump",
            "dump credentials",
            "lsass dump",
            "password dumping"
        ]
    },

    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "keywords": [
            "lsass",
            "lsass memory",
            "dump lsass",
            "lsass dump"
        ]
    },


    # ---------------- DISCOVERY ----------------

    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "keywords": [
            "system information",
            "system discovery",
            "operating system discovery",
            "hostname",
            "system information discovery"
        ]
    },

    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "keywords": [
            "file discovery",
            "directory discovery",
            "list files",
            "enumerate files",
            "file system discovery"
        ]
    },

    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "keywords": [
            "remote system discovery",
            "network discovery",
            "discover remote systems",
            "enumerate remote hosts"
        ]
    },

    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "keywords": [
            "network scanning",
            "port scanning",
            "network service scanning",
            "scan ports",
            "service scan"
        ]
    },


    # ---------------- COMMAND AND CONTROL ----------------

    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": [
            "download payload",
            "download file",
            "download malware",
            "downloaded payload",
            "retrieve payload",
            "transfer tool"
        ]
    },

    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "keywords": [
            "http communication",
            "https communication",
            "http c2",
            "https c2",
            "web protocol",
            "command and control over http"
        ]
    },


    # ---------------- IMPACT ----------------

    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": [
            "encrypted files",
            "file encryption",
            "encrypt files",
            "ransomware encryption",
            "encrypted data"
        ]
    },

    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "keywords": [
            "delete shadow copies",
            "shadow copies deleted",
            "disable recovery",
            "inhibit recovery",
            "system recovery"
        ]
    }
}


# ============================================================
# MITRE TACTIC ORDER
# ============================================================

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]


# ============================================================
# PARENT / SUB-TECHNIQUE RELATIONSHIPS
# ============================================================

PARENT_CHILD_PAIRS = {

    "T1059": [
        "T1059.001",
        "T1059.003",
        "T1059.004"
    ],

    "T1566": [
        "T1566.001",
        "T1566.002"
    ],

    "T1003": [
        "T1003.001"
    ]
}


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text):

    if text is None:
        return ""

    text = str(text).lower()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# BUILD CONTEXT FROM RETRIEVER RESULTS
# ============================================================

def build_context(retrieved_results):

    """
    Converts Retriever Agent output into a single
    context string.

    Expected format:

    [
        {
            "source": "...",
            "page": 1,
            "text": "..."
        }
    ]
    """

    if not retrieved_results:
        return ""

    context_parts = []

    for result in retrieved_results:

        if isinstance(result, dict):

            source = result.get(
                "source",
                "Unknown source"
            )

            page = result.get(
                "page",
                "Unknown page"
            )

            text = result.get(
                "text",
                ""
            )

            context_parts.append(
                f"""
Source: {source}
Page: {page}

Text:
{text}
"""
            )

        else:

            context_parts.append(
                str(result)
            )

    return "\n\n".join(
        context_parts
    )


# ============================================================
# LOCAL MITRE KEYWORD MATCHING
# ============================================================

def match_mitre_techniques(text):

    """
    Performs deterministic keyword matching.

    This is used as a grounding layer alongside
    Groq semantic analysis.
    """

    normalized_text = normalize_text(
        text
    )

    mappings = []

    if not normalized_text:
        return mappings

    for technique_id, technique in MITRE_TECHNIQUES.items():

        matched_keywords = []

        for keyword in technique["keywords"]:

            if normalize_text(keyword) in normalized_text:

                matched_keywords.append(
                    keyword
                )

        if matched_keywords:

            confidence = min(
                0.50 +
                (0.10 * len(matched_keywords)),
                0.95
            )

            mappings.append({

                "technique_id":
                    technique_id,

                "technique_name":
                    technique["name"],

                "tactic":
                    technique["tactic"],

                "confidence":
                    round(
                        confidence,
                        2
                    ),

                "matched_keywords":
                    matched_keywords

            })

    return mappings


# ============================================================
# GROQ SEMANTIC MITRE ANALYSIS
# ============================================================

def groq_mitre_analysis(context):

    """
    Uses Groq to semantically identify MITRE
    ATT&CK techniques from retrieved CTI context.
    """

    technique_catalog = []

    for technique_id, technique in MITRE_TECHNIQUES.items():

        technique_catalog.append({

            "technique_id":
                technique_id,

            "name":
                technique["name"],

            "tactic":
                technique["tactic"]

        })

    catalog = json.dumps(
        technique_catalog,
        indent=2
    )


    system_prompt = f"""
You are a Cyber Threat Intelligence analyst
specialized in the MITRE ATT&CK framework.

Analyze the provided cybersecurity information
and identify attacker behaviors that correspond
to MITRE ATT&CK techniques.

STRICT RULES:

1. Use ONLY the provided context.
2. Do NOT use outside information.
3. Only select techniques from the provided
   MITRE catalog.
4. NEVER invent a MITRE technique ID.
5. Do not map a technique unless there is
   behavioral evidence in the context.
6. Prefer specific sub-techniques when
   supported by evidence.
7. Give a confidence score between 0.0 and 1.0.
8. Provide a short evidence statement.
9. Return ONLY valid JSON.

MITRE CATALOG:

{catalog}
"""


    user_prompt = f"""
Analyze the following retrieved cybersecurity
context.

================ CONTEXT ================

{context}

==========================================

Identify the MITRE ATT&CK techniques supported
by the evidence.

Return exactly:

{{
    "techniques": [
        {{
            "technique_id": "T1059.001",
            "confidence": 0.95,
            "evidence": "The report states that PowerShell was used to execute commands."
        }}
    ]
}}

If no techniques are supported, return:

{{
    "techniques": []
}}
"""


    response = llm_client.chat.completions.create(

        model=GROQ_MODEL,

        messages=[

            {
                "role": "system",
                "content": system_prompt
            },

            {
                "role": "user",
                "content": user_prompt
            }

        ],

        temperature=0,

        response_format={
            "type": "json_object"
        }
    )


    content = response.choices[0].message.content

    if not content:
        return []

    try:

        data = json.loads(
            content
        )

    except json.JSONDecodeError:

        print(
            "Warning: Groq returned invalid JSON."
        )

        return []

    return data.get(
        "techniques",
        []
    )


# ============================================================
# VALIDATE GROQ OUTPUT
# ============================================================

def validate_groq_mappings(
    groq_mappings,
    local_mappings
):

    """
    Validates Groq output against the local
    MITRE knowledge base.

    Unknown or hallucinated technique IDs
    are rejected.
    """

    validated = []

    local_mapping_dict = {

        mapping["technique_id"]:
            mapping

        for mapping in local_mappings

    }


    for item in groq_mappings:

        technique_id = item.get(
            "technique_id"
        )


        # ------------------------------------
        # Reject unknown IDs
        # ------------------------------------

        if technique_id not in MITRE_TECHNIQUES:

            print(
                f"Rejected unknown MITRE ID: "
                f"{technique_id}"
            )

            continue


        technique = MITRE_TECHNIQUES[
            technique_id
        ]


        # ------------------------------------
        # Confidence
        # ------------------------------------

        try:

            confidence = float(
                item.get(
                    "confidence",
                    0.0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            confidence = 0.0


        confidence = max(
            0.0,
            min(
                confidence,
                1.0
            )
        )


        # ------------------------------------
        # Local keyword evidence
        # ------------------------------------

        local_match = local_mapping_dict.get(
            technique_id
        )

        matched_keywords = []

        if local_match:

            matched_keywords = local_match[
                "matched_keywords"
            ]


        # ------------------------------------
        # Final validated mapping
        # ------------------------------------

        validated.append({

            "technique_id":
                technique_id,

            "technique_name":
                technique["name"],

            "tactic":
                technique["tactic"],

            "confidence":
                round(
                    confidence,
                    2
                ),

            "evidence":
                item.get(
                    "evidence",
                    "Behavior identified from retrieved context."
                ),

            "matched_keywords":
                matched_keywords

        })


    return validated


# ============================================================
# REMOVE REDUNDANT PARENT TECHNIQUES
# ============================================================

def remove_redundant_parent_techniques(
    mappings
):

    detected_ids = {

        mapping["technique_id"]

        for mapping in mappings

    }

    filtered = []

    for mapping in mappings:

        technique_id = mapping[
            "technique_id"
        ]


        if technique_id in PARENT_CHILD_PAIRS:

            children = PARENT_CHILD_PAIRS[
                technique_id
            ]


            if any(
                child in detected_ids
                for child in children
            ):

                continue


        filtered.append(
            mapping
        )


    return filtered


# ============================================================
# SORT MAPPINGS
# ============================================================

def sort_mappings(mappings):

    tactic_index = {

        tactic: index

        for index, tactic in enumerate(
            TACTIC_ORDER
        )

    }


    return sorted(

        mappings,

        key=lambda mapping: (

            tactic_index.get(
                mapping["tactic"],
                len(TACTIC_ORDER)
            ),

            mapping["technique_id"]

        )

    )


# ============================================================
# CREATE ATTACK FLOW
# ============================================================

def create_attack_flow(mappings):

    detected_tactics = {

        mapping["tactic"]

        for mapping in mappings

    }


    return [

        tactic

        for tactic in TACTIC_ORDER

        if tactic in detected_tactics

    ]


# ============================================================
# CREATE SUMMARY
# ============================================================

def create_technique_summary(mappings):

    if not mappings:

        return (
            "No MITRE ATT&CK techniques identified."
        )


    return "; ".join(

        f"{mapping['technique_id']} - "
        f"{mapping['technique_name']}"

        for mapping in mappings

    )


# ============================================================
# MITRE MAPPER AGENT
# ============================================================

def mitre_mapper_agent(retrieved_results):

    """
    MITRE Mapper Agent.

    INPUT:
        Retrieved results from the Retriever Agent.

    OUTPUT:
        Structured dictionary containing:

        - MITRE ATT&CK techniques
        - Technique IDs
        - Tactics
        - Confidence scores
        - Evidence
        - Attack flow
        - Summary

    Architecture:

        Retriever
             ↓
        retrieved_results
             ↓
        MITRE Mapper
             ↓
        Local MITRE KB + Groq
             ↓
        Validated ATT&CK Mapping
             ↓
        Attack Flow
    """

    print(
        "\n=========================================="
    )

    print(
        "MITRE MAPPER AGENT"
    )

    print(
        "=========================================="
    )


    # ========================================================
    # STEP 1 — BUILD CONTEXT
    # ========================================================

    print(
        "\n[1/4] Processing retrieved CTI context..."
    )


    context = build_context(
        retrieved_results
    )


    if not context:

        print(
            "No retrieved context provided."
        )


        return {

            "agent":
                "MITRE Mapper",

            "status":
                "no_input",

            "mappings":
                [],

            "attack_flow":
                [],

            "total_techniques":
                0,

            "summary":
                "No retrieved context provided."

        }


    # ========================================================
    # STEP 2 — LOCAL MITRE MATCHING
    # ========================================================

    print(
        "\n[2/4] Running local MITRE matching..."
    )


    local_mappings = match_mitre_techniques(
        context
    )


    print(
        f"Local candidates found: "
        f"{len(local_mappings)}"
    )


    # ========================================================
    # STEP 3 — GROQ SEMANTIC ANALYSIS
    # ========================================================

    print(
        "\n[3/4] Running Groq semantic analysis..."
    )


    try:

        groq_mappings = groq_mitre_analysis(
            context
        )


        print(
            f"Groq candidates found: "
            f"{len(groq_mappings)}"
        )


    except Exception as error:

        print(
            "\nGroq API error:"
        )

        print(
            str(error)
        )

        print(
            "\nFalling back to local MITRE matching."
        )

        groq_mappings = []


    # ========================================================
    # STEP 4 — VALIDATE GROQ OUTPUT
    # ========================================================

    print(
        "\n[4/4] Validating MITRE mappings..."
    )


    if groq_mappings:

        mappings = validate_groq_mappings(

            groq_mappings,

            local_mappings

        )

    else:

        mappings = local_mappings


        for mapping in mappings:

            mapping["evidence"] = (
                "Behavior matched using "
                "local MITRE keyword rules."
            )


    # ========================================================
    # REMOVE REDUNDANT PARENT TECHNIQUES
    # ========================================================

    mappings = remove_redundant_parent_techniques(
        mappings
    )


    # ========================================================
    # REMOVE DUPLICATES
    # ========================================================

    unique_mappings = {}


    for mapping in mappings:

        technique_id = mapping[
            "technique_id"
        ]


        unique_mappings[
            technique_id
        ] = mapping


    mappings = list(
        unique_mappings.values()
    )


    # ========================================================
    # SORT MAPPINGS
    # ========================================================

    mappings = sort_mappings(
        mappings
    )


    # ========================================================
    # CREATE ATTACK FLOW
    # ========================================================

    attack_flow = create_attack_flow(
        mappings
    )


    # ========================================================
    # CREATE SUMMARY
    # ========================================================

    summary = create_technique_summary(
        mappings
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "agent":
            "MITRE Mapper",

        "status":
            "success",

        "mappings":
            mappings,

        "attack_flow":
            attack_flow,

        "total_techniques":
            len(mappings),

        "summary":
            summary

    }


    # ========================================================
    # DISPLAY HUMAN-READABLE RESULT
    # ========================================================

    print(
        "\n=========================================="
    )

    print(
        "MITRE ATT&CK MAPPING"
    )

    print(
        "=========================================="
    )


    if not mappings:

        print(
            "No MITRE ATT&CK techniques identified."
        )

    else:

        for mapping in mappings:

            print(
                f"\n{mapping['technique_id']} - "
                f"{mapping['technique_name']}"
            )

            print(
                "Tactic:",
                mapping["tactic"]
            )

            print(
                "Confidence:",
                mapping["confidence"]
            )

            print(
                "Evidence:",
                mapping["evidence"]
            )


            if mapping[
                "matched_keywords"
            ]:

                print(
                    "Matched keywords:",
                    ", ".join(
                        mapping[
                            "matched_keywords"
                        ]
                    )
                )


    # ========================================================
    # DISPLAY ATTACK FLOW
    # ========================================================

    print(
        "\n=========================================="
    )

    print(
        "ATTACK FLOW"
    )

    print(
        "=========================================="
    )


    if attack_flow:

        print(
            " → ".join(
                attack_flow
            )
        )

    else:

        print(
            "No attack flow identified."
        )


    # ========================================================
    # RETURN STRUCTURED RESULT
    # ========================================================

    return result


# ============================================================
# STANDALONE TEST
# ============================================================

def run_test():

    print(
        "\n=========================================="
    )

    print(
        "MITRE MAPPER TEST"
    )

    print(
        "=========================================="
    )


    # --------------------------------------------------------
    # Simulated Retriever Agent output
    # --------------------------------------------------------

    test_retrieved_results = [

        {

            "source":
                "sample_threat_report.pdf",

            "page":
                4,

            "text":
                """
                The attacker gained initial access
                through a phishing email containing
                a malicious document.

                The malicious document executed
                PowerShell commands on the victim system.

                The attacker downloaded a malicious
                payload from a remote server.

                Credentials were dumped from
                LSASS memory.

                Windows Defender was disabled
                to evade detection.

                Finally, files on the victim system
                were encrypted.
                """

        }

    ]


    # --------------------------------------------------------
    # Run MITRE Mapper
    # --------------------------------------------------------

    result = mitre_mapper_agent(
        test_retrieved_results
    )


    # --------------------------------------------------------
    # IMPORTANT:
    #
    # We intentionally DO NOT print the JSON here.
    #
    # The result is still returned by
    # mitre_mapper_agent() and can be consumed
    # by the Planner/Orchestrator and Report Generator.
    # --------------------------------------------------------

    return result


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    run_test()