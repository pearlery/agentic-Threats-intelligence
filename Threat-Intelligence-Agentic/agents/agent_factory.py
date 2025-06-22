from langchain import hub
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import Tool, AgentExecutor, create_react_agent
from langchain_experimental.plan_and_execute import (
    PlanAndExecute,
    load_agent_executor,
    load_chat_planner
)

from config import Config
from tools.threat_intelligence_tools import IPIntelligenceTool
from tools.threat_intelligence_tools import GeolocationTool
from tools.threat_intelligence_tools import MalwareAnalysisTool
from tools.threat_intelligence_tools import ThreatScoreAssessmentTool
from tools.threat_intelligence_tools import Retrieve_IP_Info

class ThreatIntelAgentFactory:
    def __init__(self, config: Config):
        self.config = config
        self.llm = ChatGoogleGenerativeAI(
            model=config.LLM_MODEL,
            temperature=config.LLM_TEMPERATURE
        )

        # Initialize tools
        self.ip_intel_tool = IPIntelligenceTool(config)
        self.geolocation_tool = GeolocationTool(config)
        self.malware_tool = MalwareAnalysisTool(config)
        self.threat_Score_Assessment_tool = ThreatScoreAssessmentTool(config)
        self.retrieve_IP_Info_tool = Retrieve_IP_Info(config)

    def _create_tools(self):
        """Create LangChain tools"""
        return [
            Tool(
                name="IP_Intelligence",
                func=self.ip_intel_tool.process,
                description="Retrieve threat intelligence for an IP address"
            ),
            Tool(
                name="Geolocation",
                func=self.geolocation_tool.process,
                description="Perform geolocation lookup for an IP address, providing city, region, country, and organization details"
            ),
            Tool(
                name="Malware_Analysis",
                func=self.malware_tool.process,
                description="Analyze file hash for malware characteristics"
            ),
            Tool(
                name="Threat_Score_Assessment",
                func=self.threat_Score_Assessment_tool.process,
                description="Calculate a comprehensive threat score for an IP address based on multiple intelligence sources"
            ),
            Tool(
                name="Retrieve_IP_Info",
                func=self.retrieve_IP_Info_tool.process,
                description="Retrieve threat intelligence information for an IP address from VirusTotal"
            ),
        ]

    def create_react_agent(self):
        """Create a React-style agent"""
        tools = self._create_tools()
        base_prompt = hub.pull("langchain-ai/react-agent-template")
        prompt = base_prompt.partial(instructions="Utilize tools to answer threat intelligence queries")

        react_agent = create_react_agent(self.llm, tools, prompt)
        return AgentExecutor(agent=react_agent, tools=tools, verbose=True)

    def create_plan_execute_agent(self):
        """Create a Plan-and-Execute agent"""
        tools = self._create_tools()
        planner = load_chat_planner(self.llm)
        executor = load_agent_executor(self.llm, tools, verbose=True)

        return PlanAndExecute(planner=planner, executor=executor)