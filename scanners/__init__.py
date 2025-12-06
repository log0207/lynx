from .sqli import SQLiScanner
from .xss import SeleniumXSSScanner
from .injection import HTMLInjectionScanner, CommandInjectionScanner, XXEScanner, LFIScanner
from .misconfig import SecurityHeadersCheck, CORSCheck, CMSScanner

# Placeholder for scanners that were empty/not implemented yet
# from .placeholders import RedirectScanner, AuthScanner, CSRFCheck, FormSecurityCheck, APIScanner

def get_all_scanners():
    return [
        SQLiScanner,
        SeleniumXSSScanner,
        HTMLInjectionScanner,
        CommandInjectionScanner,
        XXEScanner,
        LFIScanner,
        SecurityHeadersCheck,
        CORSCheck,
        CMSScanner
    ]
