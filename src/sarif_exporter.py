import json
from typing import List
from src.models import Finding

def generate_sarif_report(findings: List[Finding]) -> str:
    """
    Converts multi-agent findings into an industry-standard SARIF/JSON 
    compliance report suitable for GitHub Actions and CI/CD pipelines.
    """
    sarif_data = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Code Review Multi-Agent SAST",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/ai-code-reviewer/m2-pipeline"
                    }
                },
                "results": []
            }
        ]
    }

    for finding in findings:
        # Map severity to SARIF levels
        level = "error" if finding.severity == "High" else "warning"
        
        result_entry = {
            "ruleId": finding.cwe or finding.category,
            "level": level,
            "message": {
                "text": finding.message
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "source_code_input"
                        },
                        "region": {
                            "startLine": finding.line_number if finding.line_number else 1
                        }
                    }
                }
            ],
            "properties": {
                "agent": finding.agent,
                "category": finding.category,
                "owasp": finding.owasp,
                "recommendation": finding.recommendation
            }
        }
        sarif_data["runs"][0]["results"].append(result_entry)

    return json.dumps(sarif_data, indent=4)