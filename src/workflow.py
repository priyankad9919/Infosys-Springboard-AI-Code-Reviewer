import concurrent.futures
from typing import List
from src.models import Finding
from src.agents.code_analysis_agent import run_code_analysis
from src.agents.security_agent import run_security_scan

def run_analysis_pipeline(code_content: str, language: str) -> List[Finding]:
    """
    Orchestrates the multi-agent pipeline concurrently and groups 
    multiple findings on the same line into a single consolidated finding.
    """
    findings = []
    
    # Run both agents in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        security_future = executor.submit(run_security_scan, code_content, language)
        quality_future = executor.submit(run_code_analysis, code_content, language)
        
        findings.extend(security_future.result())
        findings.extend(quality_future.result())
        
    # --- Grouping and Merging Findings by Line Number ---
    line_map = {}
    
    for f in findings:
        line_no = f.line_number if f.line_number is not None else 0
        
        if line_no not in line_map:
            # First time seeing this line, store it directly
            line_map[line_no] = f
        else:
            # Line already exists: Merge messages and keep the highest severity
            existing = line_map[line_no]
            
            # Upgrade severity to High if either is High
            if f.severity == "High" and existing.severity != "High":
                existing.severity = "High"
                
            # Combine messages and recommendations if they differ
            if f.message not in existing.message:
                existing.message += f" | {f.message}"
            if f.recommendation and f.recommendation not in (existing.recommendation or ""):
                existing.recommendation = (existing.recommendation or "") + f" Appended Fix: {f.recommendation}"
                
    return list(line_map.values())