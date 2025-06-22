import os
from dotenv import load_dotenv

class Config:
    def __init__(self):
        # โหลดตัวแปรสภาพแวดล้อมจากไฟล์ .env
        load_dotenv()

        # API Keys สำหรับ Threat Intelligence Providers
        self.VIRUSTOTAL_KEY = os.getenv('VIRUSTOTAL_API_KEY')
        self.IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')

        # Google API Key สำหรับ LLM (Google Generative AI)
        self.GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

        # การตั้งค่า LLM (ตั้งค่า default กรณีไม่มีใน .env)
        self.LLM_MODEL = os.getenv('LLM_MODEL', 'gemini-2.0-flash-lite')
        self.LLM_TEMPERATURE = float(os.getenv('LLM_TEMPERATURE', 0.05))

        # ตรวจสอบค่าที่จำเป็นต้องมี
        self._validate_config()

    def _validate_config(self):
        missing = []
        if not self.VIRUSTOTAL_KEY:
            missing.append("VIRUSTOTAL_API_KEY")
        if not self.IPINFO_API_KEY:
            missing.append("IPINFO_API_KEY")
        if not self.GOOGLE_API_KEY:
            missing.append("GOOGLE_API_KEY")

        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

    def get_provider_settings(self):
        return {
            'virustotal': {'api_key': self.VIRUSTOTAL_API_KEY},
            'ipinfo': {'api_key': self.IPINFO_API_KEY}
        }
