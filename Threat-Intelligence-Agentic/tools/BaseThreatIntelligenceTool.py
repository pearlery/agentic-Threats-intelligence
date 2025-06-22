import abc
import json
from typing import Dict, Any


class BaseThreatIntelligenceTool(abc.ABC):
    def __init__(self, config=None):
        """
        Initialize the base tool with optional configuration

        Args:
            config (object, optional): Configuration object. Defaults to None.
        """
        self.config = config

    @abc.abstractmethod
    def process(self, input_data: str) -> Dict[str, Any]:
        """
        Abstract method to process input and return threat intelligence

        Args:
            input_data (str): Input data to analyze (IP, hash, etc.)

        Returns:
            dict: Processed threat intelligence data
        """
        pass

    def _safe_json_parse(self, data: str) -> Dict[str, Any]:
        """
        Safely parse JSON with error handling

        Args:
            data (str): JSON string to parse

        Returns:
            dict: Parsed JSON data or error dictionary
        """
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            return {
                "error": f"JSON parsing failed: {str(e)}",
                "raw_data": data
            }