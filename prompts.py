import json
from typing import List

from groq import BaseModel
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

groq_api_key = "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"

owasp = """
    A01:2025 - Broken Access Control
    A02:2025 - Security Misconfiguration
    A03:2025 - Software Supply Chain Failures
    A04:2025 - Cryptographic Failures
    A05:2025 - Injection
    A06:2025 - Insecure Design
    A07:2025 - Authentication Failures
    A08:2025 - Software or Data Integrity Failures
    A09:2025 - Security Logging and Alerting Failures
    A10:2025 - Mishandling of Exceptional Conditions
"""

llm = None


class finding(BaseModel):
    file: str
    line: str
    owasp_category: str
    risk_summary: str
    fix_recommendation: str
    confidence_score: float


class findingList(BaseModel):
    findings: List[finding]


def set_groq():
    global llm
    if llm is None:
        llm = ChatGroq(
            model_name="llama-3.3-70b-versatile", temperature=0.1, api_key=groq_api_key
        )
    return


def first_prompt():
    global llm
    set_groq()
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """You are an AppSec reviewer. Your task is to review the provided code, using the following OWASP Top 10 (2025) taxonomy only:
                A01:2025 - Broken Access Control
                A02:2025 - Security Misconfiguration
                A03:2025 - Software Supply Chain Failures
                A04:2025 - Cryptographic Failures
                A05:2025 - Injection
                A06:2025 - Insecure Design
                A07:2025 - Authentication Failures
                A08:2025 - Software or Data Integrity Failures
                A09:2025 - Security Logging and Alerting Failures
                A10:2025 - Mishandling of Exceptional Conditions
                Do not hallucinate file names or lines
                and for all vulnerabilities or risks found, provide the following:
            {{
                "file": "{file_path}",
                "line": "from the input, extract the vulnerable code and put it here, and which line number it was extracted from",
                "owasp_category": "which OWASP Top 10:2025 category the finding belongs to here",
                "risk_summary": "risk summary of 2 or 3 lines here",
                "fix_recommendation": "specific recommended fix for the issue here",
                "confidence_score": confidence score between 0 and 1 here,
            }}""",
            ),
            ("user", "{input}"),
        ]
    )

    chain = prompt | llm.with_structured_output(findingList)
    return chain


def aggregation_prompt():
    global llm
    set_groq()
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """Role:
                    You are a Security Report Optimizer. Your goal is to consolidate redundant findings into a single representative entry per vulnerability type per file.

                    Primary Key for Deduplication:
                    A finding is considered a "Duplicate" if it shares the same [file] AND describes the same [Specific Vulnerability Root Cause] (e.g., Hardcoded Credentials).

                    Instructions:
                    1. **Group by Root Cause**: Scan the "risk_summary". If multiple entries in the same file describe "Hardcoded credentials," they must be merged.
                    2. **Merge the "line" field**: Concatenate the code snippets or line numbers into a single string, separated by a semicolon or " | ".
                    3. **Score Calculation**: For the "confidence_score", do not average them. Simply use the highest score from the original group of findings.
                    4. **Consistency**: Use the most detailed "risk_summary" and "fix_recommendation" from the group for the final consolidated entry.
                    5. **Format**: Your output must be a valid JSON array of objects that strictly follow the Pydantic schema provided.

                    ### Examples of Non-Duplicates (KEEP SEPARATE)
                    - File A: SQL Injection (OWASP A03)
                    - File A: OS Command Injection (OWASP A03)
                    *Even though they share a category, they are different root causes. Keep both.*""",
            ),
            ("user", "{input}"),
        ]
    )

    chain = prompt | llm.with_structured_output(findingList)
    return chain


def parse_file(code: str, file_path: str) -> dict:
    chain = first_prompt()
    answer = chain.invoke({"input": code, "file_path": file_path})
    result = answer.model_dump(mode="json")["findings"]
    result = process_result(result)
    return result


def second_pass(code):
    chain = aggregation_prompt()
    answer = chain.invoke({"input": json.dumps(code)})
    result = answer.model_dump(mode="json")["findings"]
    return result


def process_result(result):
    mapping = {
        "A01:2025": "A01:2025 - Broken Access Control",
        "A02:2025": "A02:2025 - Security Misconfiguration",
        "A03:2025": "A03:2025 - Software Supply Chain Failures",
        "A04:2025": "A04:2025 - Cryptographic Failures",
        "A05:2025": "A05:2025 - Injection",
        "A06:2025": "A06:2025 - Insecure Design",
        "A07:2025": "A07:2025 - Authentication Failures",
        "A08:2025": "A08:2025 - Software or Data Integrity Failures",
        "A09:2025": "A09:2025 - Security Logging and Alerting Failures",
        "A10:2025": "A10:2025 - Mishandling of Exceptional Conditions",
    }
    for finding in result:
        finding["owasp_category"] = mapping.get(
            finding["owasp_category"], finding["owasp_category"]
        )
    return result
