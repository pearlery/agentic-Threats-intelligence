import streamlit as st
import json
from config.Config import Config
from agents.agent_factory import ThreatIntelAgentFactory

class ThreatIntelStreamlitApp:
    def __init__(self):
        self.config = Config()
        self.agent_factory = ThreatIntelAgentFactory(self.config)

    def _render_sidebar(self):
        st.sidebar.header("🌸 Threat Intelligence Config")

        self.agent_type = st.sidebar.radio(
            "🧠 Select Agent Type",
            ["🌼 React Agent", "📋 Plan and Execute Agent"],
            index=0
        )

        st.sidebar.markdown("""
        ### 💡 Example Queries:
        - IP: `77.246.107.91`
        - Hash: `abc123`
        - Analyze threat level
        """)

    def _process_query(self, query):
        try:
            if self.agent_type == "🌼 React Agent":
                agent = self.agent_factory.create_react_agent()
                result = agent.invoke({"input": query})
            else:
                agent = self.agent_factory.create_plan_execute_agent()
                result = agent.invoke(query)
            return result
        except Exception as e:
            return {"error": str(e)}

    def run(self):
        # 🌈 พาสเทลธีมด้วย CSS
        st.markdown("""
            <style>
                body {
                    background-color: #fdf6f0;
                }
                .stApp {
                    background-color: #fff9f9;
                    color: #4f4f4f;
                    font-family: "Comic Sans MS", cursive, sans-serif;
                }
                h1 {
                    color: #ffb6b9;
                }
                .stButton>button {
                    background-color: #ffcad4;
                    color: white;
                    font-weight: bold;
                    border-radius: 10px;
                    padding: 10px;
                }
                .stTextInput>div>div>input {
                    background-color: #fff0f5;
                }
                .stSidebar {
                    background-color: #ffe4e1;
                }
            </style>
        """, unsafe_allow_html=True)

        st.title("🧁 Threat Intelligence Analysis")

        self._render_sidebar()

        query = st.text_input("🔎 Enter IP, Hash, or Threat Query:", placeholder="e.g., 77.246.107.91")

        if st.button("🕵️‍♀️ Analyze Threat"):
            if not query:
                st.warning("⚠️ Please enter a query")
                return

            with st.spinner("🌀 Analyzing Threat Intelligence..."):
                result = self._process_query(query)
        st.title("🛡️ Threat Intelligence Agentic UI")

        # UI แบบเลือกหน้า
        tab = st.sidebar.radio("🔍 View", ["🧠 Ask Agent", "📋 View Alert History"])

        if tab == "🧠 Ask Agent":
            query = st.text_input("Ask the Agent", placeholder="Ex. Analyze alert: 77.246.107.91")
            if query:
                result = self._process_query(query)
                st.markdown("### 🧠 Result")
                st.json(result)
        elif tab == "📋 View Alert History":
            display_alert_history()



            st.subheader("📊 Result")
            st.json(result)


def main():
    app = ThreatIntelStreamlitApp()
    app.run()

if __name__ == "__main__":
    main()

    
# import streamlit as st
# import json
# from config.Config import Config
# from agents.agent_factory import ThreatIntelAgentFactory

# class ThreatIntelStreamlitApp:
#     def __init__(self):
#         # Initialize configuration and agent factory
#         self.config = Config()
#         self.agent_factory = ThreatIntelAgentFactory(self.config)

#     def _render_sidebar(self):
#         """Render sidebar with configuration options"""
#         st.sidebar.header("Threat Intelligence Configuration")

#         self.agent_type = st.sidebar.radio(
#             "Select Agent Type",
#             ["React Agent", "Plan and Execute Agent"],
#             index=0
#         )

#         st.sidebar.markdown("""
#         ### Example Queries:
#         - IP: 77.246.107.91
#         - Hash: abc123
#         - Analyze threat level
#         """)

#     def _process_query(self, query):
#         """Process query using selected agent"""
#         try:
#             # Select agent based on user choice
#             if self.agent_type == "React Agent":
#                 agent = self.agent_factory.create_react_agent()
#                 result = agent.invoke({"input": query})
#             else:
#                 agent = self.agent_factory.create_plan_execute_agent()
#                 result = agent.invoke(query)

#             return result
#         except Exception as e:
#             return {"error": str(e)}

#     def run(self):
#         """Main Streamlit application"""
#         st.title("Threat Intelligence Analysis")

#         # Render sidebar
#         self._render_sidebar()

#         # Query input
#         query = st.text_input("Enter IP, Hash, or Threat Query:", placeholder="e.g., 77.246.107.91")

#         # Process query on button click
#         if st.button("Analyze Threat"):
#             if not query:
#                 st.warning("Please enter a query")
#                 return

#             with st.spinner("Analyzing Threat Intelligence..."):
#                 result = self._process_query(query)

#             # Display results
#             st.json(result)


# def main():
#     app = ThreatIntelStreamlitApp()
#     app.run()


# if __name__ == "__main__":
#     main()
