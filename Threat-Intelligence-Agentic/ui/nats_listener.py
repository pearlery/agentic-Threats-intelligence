import asyncio
import json
from nats.aio.client import Client as NATS
from triage.triage_logic import triage_alert
from agents.agent_factory import ThreatIntelAgentFactory
from config.Config import Config


class NATSAlertListener:
    def __init__(self, nats_url="nats://localhost:4222", subject="alerts.telemetry"):
        self.nats_url = nats_url
        self.subject = subject
        self.config = Config()
        self.agent_factory = ThreatIntelAgentFactory(self.config)

    async def connect_and_listen(self):
        nc = NATS()
        await nc.connect(self.nats_url)

        print(f"✅ Connected to NATS at {self.nats_url}, listening on '{self.subject}'")

        async def message_handler(msg):
            data = msg.data.decode()
            print(f"\n📩 Received alert: {data}")

            try:
                alert = json.loads(data)

                # 🔎 Step 1: Triage
                triage_result = triage_alert(alert)
                print(f"🧪 Triage Result: {triage_result}")

                # 🧠 Step 2: Use Agent to enrich/analyze
                agent = self.agent_factory.create_react_agent()
                result = agent.invoke({"input": json.dumps(alert)})

                print(f"🤖 Agent Output:\n{result}\n")

                # ✍️ (Optional) Save to log or database
                # ✍️ Save alert log + triage result to file
                alert_log = {
                    "alert": alert,
                    "triage": triage_result
                }

                with open("data/alert_history.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert_log) + "\n")

            except Exception as e:
                print(f"❌ Error: {str(e)}")

        await nc.subscribe(self.subject, cb=message_handler)
        print("🚀 Waiting for alerts... (Press Ctrl+C to stop)")
        while True:
            await asyncio.sleep(1)


# ✅ Run this only if directly called
if __name__ == "__main__":
    listener = NATSAlertListener()
    asyncio.run(listener.connect_and_listen())
