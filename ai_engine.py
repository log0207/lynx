import google.generativeai as genai
import os
import asyncio
from common import event_manager

class AIEngine:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    async def generate_executive_summary(self, findings: list) -> str:
        if not findings:
            return "No vulnerabilities found during the scan."
        
        prompt = self._build_prompt(findings)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: self.model.generate_content(prompt)
            )
            
            if response and response.text:
                return response.text
            else:
                return "AI analysis completed but no summary was generated."
                
        except Exception as e:
            error_msg = f"AI analysis failed: {str(e)}"
            await event_manager.emit("log", f"[AI] {error_msg}")
            return error_msg

    def _build_prompt(self, findings: list) -> str:
        vuln_summary = {}
        for finding in findings:
            severity = finding['severity']
            vuln_type = finding['type']
            if severity not in vuln_summary:
                vuln_summary[severity] = {}
            if vuln_type not in vuln_summary[severity]:
                vuln_summary[severity][vuln_type] = 0
            vuln_summary[severity][vuln_type] += 1

        prompt = "Generate a concise executive summary for this web application security scan. Do NOT use markdown. Use plain text with clear section headers.\n\n"
        prompt += "CRITICAL VULNERABILITIES FOUND:\n"
        
        for severity in ['P1', 'P2', 'P3', 'P4']:
            if severity in vuln_summary:
                prompt += f"\n{severity} Issues:\n"
                for vuln_type, count in vuln_summary[severity].items():
                    prompt += f"  - {vuln_type}: {count} instance(s)\n"

        prompt += "\nProvide a brief technical overview, business impact assessment, and remediation priorities. Keep under 200 words."
        return prompt