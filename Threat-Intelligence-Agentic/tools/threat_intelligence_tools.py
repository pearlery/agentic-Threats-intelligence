import json
import requests
from typing import Optional, Dict, Any
from msticpy.sectools.tilookup import TILookup
from msticpy.sectools.vtlookupv3.vtlookupv3 import VTLookupV3

from config import Config
from tools.BaseThreatIntelligenceTool import BaseThreatIntelligenceTool
import os

class IPIntelligenceTool(BaseThreatIntelligenceTool):
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize IPIntelligenceTool

        Args:
            config (Config, optional): Configuration object. Defaults to None.
        """
        super().__init__(config)
        self.ti_lookup = TILookup()
        self.vt_key = config.VIRUSTOTAL_KEY if config else None

    def process(self, ip_address: str) -> Dict[str, Any]:
        try:
            # Virus Total IP Lookup
            result = self.ti_lookup.lookup_ioc(
                observable=ip_address,
                ioc_type="ipv4",
                providers=["VirusTotal"]
            )
            details = result.at[0, 'RawResult']

            return {
                "ip": ip_address,
                "detected_samples": details.get('detected_communicating_samples', []),
                "undetected_samples": details.get('undetected_communicating_samples', [])
            }
        except Exception as e:
            return {"error": str(e)}


class GeolocationTool(BaseThreatIntelligenceTool):
    def __init__(self, config: Config):
        self.config = config

    def process(self, ip_address: str) -> Dict[str, Any]:
        try:
            response = requests.get(
                f'https://ipinfo.io/{ip_address}/json',
                params={'token': self.config.IPINFO_API_KEY},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            return {
                "ip": ip_address,
                "city": data.get('city', 'Unknown'),
                "region": data.get('region', 'Unknown'),
                "country": data.get('country', 'Unknown'),
                "location": data.get('loc', 'Unknown'),
                "organization": data.get('org', 'Unknown')
            }
        except requests.RequestException as e:
            return {"error": f"Geolocation lookup failed: {str(e)}"}

class Retrieve_IP_Info(BaseThreatIntelligenceTool):
    def __init__(self, config: Config):
        super().__init__(config)
        self.config = config
        self.ti_lookup = TILookup()
        self.vt_key = config.VIRUSTOTAL_KEY if config else None

    def process(self, ip_address: str) -> str:
        """Look up IP information from Virus Total"""
        try:
            result = self.ti_lookup.lookup_ioc(observable=ip_address, ioc_type="ipv4", providers=["VirusTotal"])
            details = result.at[0, 'RawResult']
            comm_samples = details.get('detected_communicating_samples', [])
            return json.dumps(comm_samples)
        except Exception as e:
            return f"IP lookup error: {str(e)}"


class MalwareAnalysisTool(BaseThreatIntelligenceTool):
    def __init__(self, config: Config):
        self.config = config
        self.vt_key = config.VIRUSTOTAL_KEY

    def process(self, file_hash: str) -> Dict[str, Any]:
        try:
            vt_lookup = VTLookupV3(self.vt_key)
            result = vt_lookup.get_object(file_hash, "file")

            if result is None:
                return {"error": "No malware information found"}

            return {
                "hash": file_hash,
                "detection_rate": result.detection_summary,
                "first_seen": result.first_submission_date,
                "last_seen": result.last_submission_date,
                "file_type": result.type,
                "reputation": result.reputation
            }
        except Exception as e:
            return {"error": str(e)}

class ThreatScoreAssessmentTool(BaseThreatIntelligenceTool):
    def __init__(self, config: Config):
        self.config = config
        self.vt_key = config.VIRUSTOTAL_KEY
        self.ti_lookup = TILookup()
        self.geolocation_api_key = os.getenv('IPINFO_API_KEY', '')

    def ip_info(self, ip_address: str) -> str:
        """Look up IP information from Virus Total"""
        try:
            result = self.ti_lookup.lookup_ioc(observable=ip_address, ioc_type="ipv4", providers=["VirusTotal"])
            details = result.at[0, 'RawResult']
            comm_samples = details.get('detected_communicating_samples', [])
            return json.dumps(comm_samples)
        except Exception as e:
            return f"IP lookup error: {str(e)}"

    def geolocate_ip(self, ip_address: str) -> str:
        """Perform geolocation lookup for an IP address with improved error handling"""
        if not self.geolocation_api_key:
            return json.dumps({"error": "Geolocation API key not configured"})

        try:
            response = requests.get(f'https://ipinfo.io/{ip_address}/json?token={self.geolocation_api_key}', timeout=10)
            response.raise_for_status()
            data = response.json()

            location_info = {
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'location': data.get('loc', 'Unknown'),
                'org': data.get('org', 'Unknown')
            }

            return json.dumps(location_info)
        except requests.RequestException as e:
            return json.dumps({"error": f"Geolocation lookup failed: {str(e)}"})

    def process(self, ip_address: str) -> str:
        """Calculate an aggregated threat score based on multiple intelligence sources"""
        try:
            vt_samples_str = self.ip_info(ip_address)
            vt_samples = json.loads(vt_samples_str)

            geolocation_str = self.geolocate_ip(ip_address)
            geolocation = json.loads(geolocation_str)

            threat_score = 0
            threat_score += min(len(vt_samples), 10)

            high_risk_countries = ['RU', 'CN', 'IR', 'KP']
            if geolocation.get('country') in high_risk_countries:
                threat_score += 5

            suspicious_orgs = ['Hosting Provider', 'Cloud Provider']
            if any(org in geolocation.get('org', '') for org in suspicious_orgs):
                threat_score += 3

            return json.dumps({
                'threat_score': threat_score,
                'details': {
                    'malicious_samples_count': len(vt_samples),
                    'location': geolocation,
                    'risk_assessment': 'High' if threat_score > 10 else 'Medium' if threat_score > 5 else 'Low'
                }
            })
        except Exception as e:
            return json.dumps({"error": f"Threat score assessment failed: {str(e)}"})

class ThreatScoreCalculator:
    HIGH_RISK_COUNTRIES = ['RU', 'CN', 'IR', 'KP']
    SUSPICIOUS_ORGS = ['Hosting Provider', 'Cloud Provider']

    @classmethod
    def calculate_threat_score(
            cls,
            ip_intelligence: Dict,
            geolocation: Dict
    ) -> Dict[str, Any]:
        threat_score = 0

        # Score based on malicious samples
        threat_score += min(len(ip_intelligence.get('detected_samples', [])), 10)

        # Score based on geographical risk
        country = geolocation.get('country')
        if country in cls.HIGH_RISK_COUNTRIES:
            threat_score += 5

        # Score based on organization
        org = geolocation.get('organization', '')
        if any(susp_org in org for susp_org in cls.SUSPICIOUS_ORGS):
            threat_score += 3

        # Determine risk level
        risk_level = (
            'High' if threat_score > 10 else
            'Medium' if threat_score > 5 else
            'Low'
        )

        return {
            "threat_score": threat_score,
            "risk_level": risk_level,
            "details": {
                "ip_intelligence": ip_intelligence,
                "geolocation": geolocation
            }
        }