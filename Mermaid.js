flowchart TD

subgraph group_group_agent["Agent host"]
  node_agent_service["Agent service<br/>orchestrator<br/>[service.py]"]
  node_agent_supervisor["Supervisor<br/>LangGraph router<br/>[supervisor.py]"]
  node_agent_specialists["Specialists<br/>role agents<br/>[specialists.py]"]
  node_agent_approval{{"Approval gate<br/>interrupt control<br/>[approval.py]"}}
  node_agent_history[("History<br/>sqlite threads<br/>[history.py]")]
  node_agent_llm["LLM client<br/>local model client<br/>[llm.py]"]
end

subgraph group_group_mcp["MCP server"]
  node_mcp_server["MCP server<br/>broker<br/>[server.py]"]
  node_mcp_auth["Auth<br/>[auth.py]"]
  node_mcp_resources["Resources<br/>resource layer<br/>[resources.py]"]
  node_mcp_siem[("SIEM backends<br/>backend adapters")]
  node_mcp_tools["Tool adapters<br/>tool surface"]
end

subgraph group_group_core["Core foundation"]
  node_adept_config["Config<br/>typed settings"]
  node_adept_shared["Shared<br/>cross-cutting"]
end

subgraph group_group_domain["Domain services"]
  node_detection_as_code["Detection-as-code<br/>rule lifecycle"]
  node_coverage["Coverage<br/>ATT&CK analysis"]
  node_intel["Intel<br/>enrichment service"]
  node_kb[("Knowledge base<br/>RAG store")]
  node_attack["Attack simulation<br/>emulation wrappers"]
  node_eval["Evaluation<br/>scoring workflows"]
end

subgraph group_group_data["Data and interfaces"]
  node_sigma_repo["Sigma repo<br/>git source<br/>[sigma_repo.py]"]
  node_external_siems[("SIEM systems<br/>external target")]
  node_external_intel["Intel sources<br/>external feeds"]
  node_external_emulation["Emulation systems<br/>external lab"]
  node_data_stores[("Local data<br/>runtime storage")]
end

node_adept_config -->|"settings"| node_agent_service
node_adept_config -->|"settings"| node_mcp_server
node_adept_shared -->|"runtime"| node_agent_service
node_adept_shared -->|"runtime"| node_mcp_server
node_agent_service -->|"orchestrates"| node_agent_supervisor
node_agent_supervisor -->|"routes to"| node_agent_specialists
node_agent_specialists -->|"tools via MCP"| node_mcp_server
node_agent_service -->|"gates actions"| node_agent_approval
node_agent_service -->|"persists"| node_agent_history
node_agent_service -->|"calls model"| node_agent_llm
node_mcp_server -->|"authenticates"| node_mcp_auth
node_mcp_server -->|"serves"| node_mcp_resources
node_mcp_server -->|"brokers"| node_mcp_siem
node_mcp_server -->|"exposes"| node_mcp_tools
node_mcp_tools -->|"reads/writes"| node_sigma_repo
node_mcp_tools -->|"queries"| node_intel
node_mcp_tools -->|"searches"| node_kb
node_mcp_tools -->|"analyzes"| node_coverage
node_mcp_tools -->|"executes"| node_detection_as_code
node_mcp_tools -->|"simulates"| node_attack
node_detection_as_code -->|"consumes"| node_sigma_repo
node_coverage -->|"consumes"| node_sigma_repo
node_coverage -->|"enriches with"| node_intel
node_intel -->|"fetches from"| node_external_intel
node_kb -->|"stores in"| node_data_stores
node_kb -->|"grounds"| node_agent_service
node_attack -->|"targets"| node_external_emulation
node_attack -->|"brokered by"| node_mcp_server
node_eval -->|"measures"| node_detection_as_code
node_mcp_siem -->|"connects to"| node_external_siems
node_agent_history -->|"persists in"| node_data_stores
node_mcp_server -->|"uses"| node_data_stores

click node_adept_config "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/config"
click node_adept_shared "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/shared"
click node_agent_service "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/agent/service.py"
click node_agent_supervisor "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/agent/supervisor.py"
click node_agent_specialists "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/agent/specialists.py"
click node_agent_approval "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/agent/approval.py"
click node_agent_history "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/agent/history.py"
click node_agent_llm "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/agent/llm.py"
click node_mcp_server "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/mcp_server/server.py"
click node_mcp_auth "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/mcp_server/auth.py"
click node_mcp_resources "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/mcp_server/resources.py"
click node_mcp_siem "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/mcp_server/siem"
click node_mcp_tools "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/mcp_server/tools"
click node_detection_as_code "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/detection_as_code"
click node_coverage "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/coverage"
click node_intel "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/intel"
click node_kb "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/kb"
click node_attack "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/attack"
click node_eval "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/tree/main/adept/eval"
click node_sigma_repo "https://github.com/akshayjain-1/adept-agentic-detection-engineering-orchestration-pipeline-and-tuning/blob/main/adept/mcp_server/sigma_repo.py"

classDef toneNeutral fill:#f8fafc,stroke:#334155,stroke-width:1.5px,color:#0f172a
classDef toneBlue fill:#dbeafe,stroke:#2563eb,stroke-width:1.5px,color:#172554
classDef toneAmber fill:#fef3c7,stroke:#d97706,stroke-width:1.5px,color:#78350f
classDef toneMint fill:#dcfce7,stroke:#16a34a,stroke-width:1.5px,color:#14532d
classDef toneRose fill:#ffe4e6,stroke:#e11d48,stroke-width:1.5px,color:#881337
classDef toneIndigo fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#312e81
classDef toneTeal fill:#ccfbf1,stroke:#0f766e,stroke-width:1.5px,color:#134e4a
class node_agent_service,node_agent_supervisor,node_agent_specialists,node_agent_approval,node_agent_history,node_agent_llm toneBlue
class node_mcp_server,node_mcp_auth,node_mcp_resources,node_mcp_siem,node_mcp_tools toneAmber
class node_adept_config,node_adept_shared toneMint
class node_detection_as_code,node_coverage,node_intel,node_kb,node_attack,node_eval toneRose
class node_sigma_repo,node_external_siems,node_external_intel,node_external_emulation,node_data_stores toneIndigo
