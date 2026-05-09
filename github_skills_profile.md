# 🚀 Software Engineer & Security Researcher

I am a versatile software engineer and security researcher with a strong focus on offensive/defensive cybersecurity, algorithmic trading, and scalable automation systems. I build robust backends, train machine learning models for high-frequency trading, and develop automated tooling to solve complex problems.

## 🛠️ Core Competencies

*   **Cybersecurity & Pentesting:** Vulnerability research (RCE, SSRF, IDOR), Network infrastructure analysis, Agentic security platforms.
*   **Machine Learning & AI:** Deep Learning (PyTorch), L2 Orderbook analysis, Predictive modeling for latency arbitrage.
*   **Automation & Scraping:** Headless browser automation, Anti-bot bypass techniques, Mobile ADB integrations, Telephony orchestration.
*   **Backend Engineering:** Python, Node.js, API Integration (REST/WebSockets), Database Design.

---

## 💻 Featured Projects

### 🛡️ AegisTwin Cybersecurity Platform
**Role:** Lead Developer / Security Architect
A dual-agent cybersecurity platform designed for robust threat detection and automated remediation.
*   Architected a highly secure production MVP ensuring strict tenant isolation via foreign key constraints.
*   Patched critical policy engine scope-bypass vulnerabilities.
*   Implemented comprehensive audit logging for autonomous agentic decisions and secured inter-agent communication flows.

### 📈 Polybot: High-Frequency Arbitrage Engine
**Role:** Quant Developer / ML Engineer
A High-Frequency Trading (HFT) bot executing latency arbitrage on the Polymarket platform against Binance price shocks.
*   **Deep Learning Pipeline:** Migrated from gradient-boosting to a PyTorch-based multi-layer perceptron trained on tick-level L2 orderbook data.
*   **Execution Engine:** Engineered real-time market data ingestion, gasless trading via CLOB and Relayer APIs, and automated PnL tracking.
*   **Reliability:** Implemented rigorous error handling for API 422 errors, market state transitions, and real-time trade monitoring to prevent stuck positions.
*   **Cloud ML Deployment:** Managed MLOps utilizing the **Azure Machine Learning SDK** (`azure-ai-ml`) for automated compute clusters, dataset versioning, and end-to-end model deployment.

### 📞 Realtor Sales Autopilot
**Role:** Full Stack Developer
A zero-subscription outbound sales automation system leveraging local Android hardware.
*   **Hardware Integration:** Orchestrated automated calls using a Poco C61 Android device connected via ADB.
*   **Call Logic:** Developed an Answering Machine Detection (AMD) heuristic and sequential hunt group routing.
*   **Integrations:** Integrated Node.js, Google Sheets API for lead management, Twilio/SMTP, and the WhatsApp Cloud API for automated follow-ups.

### 🕵️‍♂️ Advanced Vulnerability Research Tooling
**Role:** Security Researcher
Custom scripts and methodologies for high-impact bug bounties and infrastructure auditing.
*   **Network Attacks:** Developed methodologies for EAP/RADIUS handshake exploitation, "Twin-Gate" attacks, DHCP starvation, and DNS rebinding for lateral movement.
*   **Custom Probes:** Wrote Python-based exploit scripts (`safe_race_preview_probe.py`, `safe_idor_metadata_check.py`) handling complex environment configurations and network restrictions.
*   **Target Scope:** Specializing in Business Logic Flaws, Pre-Auth RCE, SSRF, and Web3 vulnerabilities.

### 🕸️ Real Estate Scraping Engine
**Role:** Automation Engineer
A high-performance web scraper designed to bypass sophisticated anti-bot systems on major real estate portals.
*   **Anti-Bot Bypass:** Reverse-engineered JSON state payloads to extract data without relying on fragile DOM-based scraping.
*   **Concurrency:** Built a scalable Node.js controller for concurrent execution of parsing modules with resilient error handling.

### 🪝 Full-Stack Exploitation & Data Exfiltration
**Role:** Offensive Security Engineer
Developed a comprehensive interception chain targeting gift card portals and transactional websites.
*   **API Hooking:** Engineered JavaScript payloads to hook `fetch` and `XMLHttpRequest` native functions, overriding them to capture sensitive JSON data.
*   **Exfiltration Server:** Built a stealthy Python/Flask collection server to log intercepted balance data.
*   **Vulnerability Chains:** Automated XSS injections via ACME challenges and identified critical environment exposures (e.g., `.env` and `.replit` misconfigurations) in cloud-hosted environments.

### 🌐 Advanced Reconnaissance & WAF Bypass
**Role:** Infrastructure Analyst
Mapped global enterprise infrastructures (e.g., Visa) and bypassed modern edge protections like Cloudflare.
*   **Origin IP Discovery:** Utilized historical DNS records, subdomain enumeration, and MX records to uncover origin servers behind CDNs.
*   **SSL Fingerprinting:** Leveraged Censys and Shodan for advanced SSL/TLS Certificate Fingerprinting (SHA1) to locate hidden infrastructure.
*   **Infrastructure Auditing:** Conducted MITM simulations and audited security headers (CSP, HSTS) using Wapiti.

### 🧠 AI Agent Engineering & Infrastructure
**Role:** AI Engineer / MLOps
Engineered and deployed private, Retrieval-Augmented Generation (RAG) systems and local LLM infrastructure.
*   **RAG Architecture:** Built custom RAG AI agents capable of processing large PDF corpora utilizing Vector Databases (**FAISS**), LangChain, and advanced embedding models.
*   **LLM Fine-Tuning:** Executed model fine-tuning and parameter-efficient training (LoRA/PEFT) on open-source weights (LLaMA 3.1, Mistral-7B).
*   **GPU & Cloud Orchestration:** Managed local deployments (Ollama, LM Studio, `llama.cpp`) alongside scalable cloud GPU architectures across **GCP Vertex AI** and Azure ML, optimizing memory allocation for A100/T4 instances.

### 🤖 AI Red Teaming & Agentic Exploitation
**Role:** AI Security Researcher
Focused on exploiting Large Language Models and orchestrating autonomous pentesting agents.
*   **Prompt Architecture:** Specialized in "Prompt Reframing" to bypass stringent AI safety filters for authorized, stealthy data exfiltration.
*   **Orchestration:** Integrated autonomous cybersecurity agents (MITRE Caldera, DeepExploit) for continuous adversarial simulation.

### 🧠 Autonomous Pentesting & Security Automation
**Role:** Security Automation Engineer
Deployed and orchestrated autonomous penetration testing agents and scalable vulnerability scanners.
*   **Adversary Emulation:** Configured and deployed **MITRE CALDERA** and evaluated autonomous bug-hunting agents like **XBOW**, **Cyber-AutoAgent**, and **Big Sleep**.
*   **Scalable Scanning:** Managed **OWASP Nettacker** deployments and integrated OSINT automation frameworks (SpiderFoot, Recon-ng).
*   **Exploit Frameworks:** Extensive usage of **Metasploit** and `msfvenom` for custom payload generation, listener configuration, and targeted exploitation workflows.
*   **Environment Engineering:** Resolved complex Python build backend failures, ensuring PEP 668 compliance, and managed system-wide dependencies across Debian/Kali environments using Docker, Poetry, and `pipx`.

### 🕵️ Reverse Engineering & Protocol Analysis
**Role:** Reverse Engineer
Analyzed complex client-server interactions, cryptographic implementations, and proprietary algorithms.
*   **WebSocket Decryption:** Analyzed real-time data streams to decipher proprietary formulas (e.g., predictive "Crash Point" algorithms), verifying cryptographic integrity via HMAC-SHA256 and "Provably Fair" mechanisms.
*   **Browser Telemetry Interception:** Authored custom JavaScript hooks (monkey-patching native APIs like `localStorage.setItem`) to intercept and analyze device fingerprinting and event telemetry.
*   **Cryptographic Predictability:** Researched the limitations of Hash-based seed systems and PRNG architectures in crash games, evaluating where traditional Machine Learning fails against cryptographic security.

### 🎯 Active Directory & Advanced Reconnaissance
**Role:** Threat Intelligence Researcher
Conducted deep-dive attack path modeling and infrastructure mapping.
*   **AD Attack Paths:** Utilized **Bloodhound** to apply graph theory for visualizing privilege escalation routes and lateral movement vulnerabilities within Active Directory.
*   **Infrastructure Fingerprinting:** Executed robust surface area mapping using `subfinder`, `wafw00f`, and `dig` to bypass WAFs and identify exposed assets.
*   **CVE Analysis:** Conducted technical impact assessments and CVSS scoring for enterprise vulnerabilities (e.g., Roundcube, BIND).
*   **Threat Mapping:** Applied the **MITRE ATT&CK** framework to classify adversary behaviors and architect proactive Red Teaming methodologies.

### ☁️ Enterprise Cloud Automation
**Role:** Automation Developer
Engineered stateful, serverless automation systems within the Google Workspace ecosystem.
*   **IPO Monitor System:** Developed an autonomous data-processing pipeline that tracks and filters financial IPO data based on offer thresholds.
*   **Google Apps Script (GAS):** Built robust event-driven triggers and implemented state management using `PropertiesService` to avoid silent failures in non-container-bound environments.
*   **API Integrations:** Seamlessly integrated the **Google Sheets API** for audit logging and the **Gmail API** for dispatching HTML-formatted financial reports.
*   **System Architecture:** Wrote comprehensive technical documentation, including deployment guides, disaster recovery procedures, and architectural diagrams.

### 🎯 WordPress Penetration Testing & Reconnaissance
**Role:** Red Team Specialist
Conducted comprehensive offensive security lifecycles targeting WordPress environments.
*   **Vulnerability Exploitation:** Identified and exploited `xmlrpc.php` vulnerabilities, using custom Python scripts (`xmlrpc_multicall.py`) for high-speed, stealthy authentication testing.
*   **WAF & Origin Discovery:** Bypassed CDNs (e.g., Cloudflare) to uncover origin servers using passive reconnaissance and DNS analysis.
*   **Tool Architecture:** Expert usage of Metasploit Framework (`wordpress_login_enum`), Gobuster, and custom Seclists wordlists for directory brute-forcing and Web/DB enumeration.
*   **Stealth Operations:** Executed "Stealth Mode" SQL Injections (SQLi) for data extraction, prioritizing silent work, log management, and rigorous cleanup.

### 📊 Big Data Analysis & Scraping
**Role:** Data Engineer
Engineered high-throughput scraping and statistical analysis pipelines.
*   **Large-Scale Ingestion:** Built Python architectures to scrape, parse, and clean massive historical datasets (e.g., processing >730,000 rows of crash data).
*   **Statistical Modeling:** Leveraged Pandas, Matplotlib, and Seaborn to visualize statistical frequency distributions, standard deviations, and probability metrics.

### 🔍 Full-Spectrum Web Reconnaissance
**Role:** Offensive Security Researcher
Mastered a complete reconnaissance pipeline from passive OSINT to active vulnerability discovery.
*   **Subdomain Enumeration:** Chained `subfinder`, `amass`, `assetfinder`, and `dnsx` for comprehensive passive and active asset discovery.
*   **Content Discovery:** Advanced directory fuzzing using `ffuf`, `feroxbuster`, and `dirsearch` with custom wordlists.
*   **JS & Parameter Analysis:** Extracted hidden endpoints and API secrets from client-side JavaScript using `LinkFinder` and `Arjun`/`ParamSpider`.
*   **Automated Vulnerability Scanning:** Integrated `Nuclei`, `Dalfox`, and `SQLMap` for fast, template-based detection of XSS, SQLi, and misconfigurations.
*   **Infrastructure Analysis:** Applied `testssl.sh`, `checkdmarc`, and `wafw00f` for TLS auditing, email security (DMARC/SPF/DKIM) validation, and WAF fingerprinting.

### 🧬 CyberOrchestrator: AI-Powered Security Platform
**Role:** Platform Architect
Designed a unified platform integrating dozens of security tools with LLM-based autonomous decision-making.
*   **Multi-Agent Orchestration:** Leveraged MITRE Caldera as the command brain to coordinate complex kill chain stages (recon → exploitation → post-exploitation).
*   **LLM Integration:** Embedded multiple LLMs (Claude, GPT-4, LLaMA, DeepSeek) for intelligent automated reasoning and adversary decision-making.
*   **Tool Wrapping:** Unified CLI security tools (Metasploit, BloodHound, Frida, Atomic Red Team) into an async Python (`asyncio`/`subprocess`) orchestration framework.

### 🕵️ Nmap Advanced Evasion & Packet Manipulation
**Role:** Network Penetration Tester
Engineered stealthy network scanning techniques to evade enterprise-grade firewalls and WAFs.
*   **Stealth Scans:** Executed SYN, FIN, Null, and Xmas scans to bypass stateless packet filters.
*   **Identity Masking:** Applied decoy scanning, MAC address spoofing, and source port manipulation for deep anonymity.
*   **Packet Engineering:** Used IP fragmentation, MTU adjustments, and data-length padding to circumvent deep packet inspection.

### 🖥️ Virtualization & Security Lab Architecture
**Role:** Lab Engineer
Architected isolated, multi-node virtual laboratory environments for offensive security research and safe malware analysis.
*   **Hypervisor Setup:** Configured VMware Workstation with dedicated Kali Linux (attacker) and Windows (target) nodes.
*   **Network Isolation:** Implemented host-only and bridged networking for controlled attack/target segmentation.

### 📱 Mobile Security & Traffic Interception
**Role:** Mobile Security Researcher
Conducted end-to-end security assessments of Android/iOS applications and mobile infrastructure.
*   **Burp Suite Mastery:** Configured advanced HTTPS proxying with SSL certificate installation for full Android/iOS mobile traffic interception and analysis.
*   **Autonomous Android Bot:** Built a standalone phone-based automation agent using Android Accessibility Services and Tasker/MacroDroid, integrated with Twilio/Plivo VoIP and WhatsApp Business API — no external server required.
*   **Smart Contract Auditing:** Applied web3 security methodologies to analyze DeFi/crypto application attack surfaces.

### 🔴 Stealth & Anonymized Attack Infrastructure
**Role:** Red Team Operator
Built anonymous, rate-limit-resistant offensive tooling for controlled security research.
*   **Traffic Anonymization:** Integrated **Proxychains** and **Tor** for multi-hop routing to bypass IP blocks during authentication testing.
*   **Session Management:** Implemented cookie/session state management in shell-scripted attack workflows.
*   **Autonomous Scanner Config:** Optimized OWASP Nettacker for large-scale, multi-threaded scanning with custom user-agents and module selection.

### 📈 Polymarket Multi-Agent Prediction System
**Role:** Quant Researcher / AI Engineer
Designed a state-of-the-art, multi-layered prediction market trading system.
*   **Ensemble ML Models:** Trained and ensembled **XGBoost**, **LightGBM**, and **LSTM/Transformer** models for time-series market forecasting.
*   **NLP & Sentiment:** Fine-tuned LLMs (GPT-4o, Claude) and deployed **FinBERT** for real-time news sentiment extraction and signal generation.
*   **Bayesian Statistics:** Applied Bayesian updating and Platt scaling for probability calibration and Brier Score tracking.
*   **Data Ops:** Ingested real-time signals from government APIs (FEC, FDA), sports data feeds, and alternative dark signal sources.

### 🎰 Binary Reverse Engineering & RNG State Cracking
**Role:** Reverse Engineer / Security Researcher
Reverse-engineered proprietary game binaries and cryptographic randomness implementations.
*   **Binary Analysis:** Decompiled game binaries with **Ghidra** to identify core logic functions (`StartRound`, `CalculateMultiplier`) and model the underlying crash point algorithm.
*   **PRNG State Inference:** Performed deep research into **Linear Congruential Generators (LCG)** and **Mersenne Twister** architectures, modeling state inference attacks (requiring 624 outputs for full Mersenne Twister state recovery).
*   **Quantum Pattern Recognition:** Investigated hybrid quantum-classical prediction approaches using **Qiskit** (`scipy.optimize`) for advanced seed inference and RNG pattern analysis.

### ⚡ WAF Evasion & High-Performance Network Scanning
**Role:** Bug Bounty Researcher
Built timing-sensitive, parallelized tooling to bypass WAFs at scale.
*   **Masscan:** Deployed as a high-parallelism port scanner using a custom async TCP/IP stack for internet-scale reconnaissance.
*   **SQLMap Tuning:** Configured custom tamper scripts, randomized parameters, and thread concurrency to evade WAF detection during time-based blind SQLi tests.
*   **Scapy:** Crafted raw async packet workflows (`sr()`, `srloop()`, `srp()`) for stealthy, low-level network probing.

### 💉 React XSS Exploitation & Token Theft
**Role:** Web Application Security Researcher
Conducted targeted attacks on React-based web applications.
*   **XSS in React:** Exploited `dangerouslySetInnerHTML` sinks to inject `<img onerror>` payloads into unsanitized input fields.
*   **Token Acquisition:** Extracted `authToken` values from `localStorage` via crafted XSS fetch payloads, enabling full session hijacking.
*   **Burp Suite Workflow:** Used Proxy + Repeater to intercept, analyze, and manipulate requests to find reflected/stored XSS entry points.

### 🕵️ Adversary Emulation on Amnesic OS (Tails)
**Role:** Red Team Infrastructure Engineer
Configured secure, isolated red team infrastructure on amnesic operating systems.
*   **Caldera on Tails OS:** Deployed and debugged the MITRE Caldera framework on Tails OS, configuring persistent storage and managing Python `venv` dependencies with recursive Git submodule handling.
*   **Isolated Lab Ops:** Designed ephemeral security testing environments ensuring zero operational trace after each engagement.

### 👻 Ghostcrew: Full Penetration Test Execution
**Role:** Lead Penetration Tester
Executed a full end-to-end penetration test engagement using the **Ghostcrew** agent framework.
*   **SQL Injection (High):** Exploited login bypass via SQLi to obtain full administrative access.
*   **SSL/TLS Weaknesses (Medium):** Identified broken transit encryption configurations enabling potential eavesdropping.
*   **Sensitive File Exposure (Medium):** Discovered exposed internal files causing significant information leakage.
*   **Attack Path:** Mapped end-to-end kill chain (Endpoint Discovery → SQLi → Privilege Escalation → Admin Compromise).

### ☁️ Professional Email Infrastructure Engineering
**Role:** DevOps / Infrastructure Engineer
Architected zero-cost professional email infrastructure for custom domains.
*   **DNS Configuration:** Configured MX, SPF, DKIM, and DMARC records for email authentication and anti-spoofing.
*   **Email Routing:** Set up **Cloudflare Email Routing** and **SMTP relay** via Gmail/Zoho for high-deliverability outbound mail.

### 🔬 LLM Research & Uncensored Model Analysis
**Role:** AI Researcher
Conducted deep comparative research into open-source and uncensored Large Language Models.
*   **Model Evaluation:** Benchmarked LLMs across parameter counts, training datasets, and content restriction policies using accuracy and precision metrics.
*   **Deployment Research:** Evaluated tradeoffs between censored mainstream models and uncensored fine-tunes (e.g., WizardLM, Dolphin) for specialized research tasks.

### 🌐 Network Traffic Analysis & Packet Inspection
**Role:** Network Security Analyst
Performed real-time network traffic analysis for security research and protocol understanding.
*   **Wireshark:** Captured and filtered live traffic using advanced display filters (`http`, `tcp.port == 443`, protocol-specific filters) to isolate application-layer communications.
*   **Traffic Correlation:** Cross-referenced captured packets with known API behavior to reverse-engineer proprietary client-server protocols.

### 🕵️ APT Research & Threat Intelligence
**Role:** Threat Intelligence Researcher
Studied Advanced Persistent Threat (APT) operations and black-hat techniques for defensive and research purposes.
*   **APT Case Studies:** Analyzed real-world APT campaigns including malware development lifecycle, C2 communications, and lateral movement techniques.
*   **Social Engineering:** Studied methodologies for human-centric attack vectors and phishing infrastructure setup.
*   **Malware Analysis:** Researched reverse engineering workflows for binary analysis and behavior profiling.

### 🐚 Shellcode Engineering & Binary Obfuscation
**Role:** Offensive Tool Developer
Developed and packaged low-level payloads for adversary emulation.
*   **Donut:** Generated position-independent shellcode from .NET assemblies, EXEs, and DLLs for injection into remote processes.
*   **UPX Packing:** Applied binary compression/obfuscation via UPX to reduce AV detection rates on custom executables.

### 🎲 Applied Cryptanalysis: Provably Fair Systems
**Role:** Cryptographic Security Researcher
Systematically reverse-engineered Provably Fair RNG implementations used in real-money online games.
*   **HMAC-SHA512 Analysis:** Decoded the full seed chain (`ServerSeed + ClientSeed + Nonce`) and reconstructed the multiplier formula: `1,000,000 / (random_value + 1) * (1 - HouseEdge)`.
*   **MT19937 State Recovery:** Executed the "624-output attack" on Mersenne Twister to recover full internal state, enabling future outcome prediction with validated MAE/accuracy metrics.
*   **LCG Lattice Reduction:** Applied the **LLL algorithm** to solve for LCG (`ax + b mod m`) parameters from output samples, reconstructing seed values.
*   **Advanced PRNG Research:** Investigated Fortuna and ChaCha20 stream ciphers and used the `randcrack` Python library for MT state cracking.
*   **ML Data Pipeline:** Debugged `scikit-learn` `StandardScaler` feature-name mismatches in live prediction models, ensuring training schema consistency.

### 🌐 Deep Infrastructure Probing & Credential Exposure
**Role:** Bug Bounty / Red Team Researcher
Discovered critical misconfigurations and sensitive data exposures on live production systems.
*   **`.env` File Exposure:** Discovered a 119KB exposed environment file containing live **Stripe API keys**, database credentials, and application secrets on a Shopify-based e-commerce target.
*   **TLS/SSL Deep Inspection:** Used `openssl s_client` to inspect TLS 1.3 session tickets, certificate chain validation (Google Trust Services), and server cipher suite negotiation.
*   **DNS Zone Transfers:** Attempted AXFR zone transfers via `dig` to enumerate full DNS record sets; diagnosed local firewall/resolver issues during engagement.
*   **PentAGI & Multi-Agent Kill Chains:** Orchestrated a complex APT simulation against scammer infrastructure using an ensemble of autonomous agents (PentAGI, Nebula, hackSynth, vulnbot, Metta, DeepExploit, AutoSploit).

### 🐳 Docker Infrastructure & Container Optimization
**Role:** DevOps / Infrastructure Engineer
Managed and optimized containerized development and security tool infrastructure.
*   **Image Lifecycle Management:** Differentiated dangling vs. unused image layers and applied targeted pruning strategies.
*   **Deep System Cleanup:** Used `docker system prune -a --volumes` for comprehensive removal of stopped containers, unused networks, orphaned volumes, and build cache.
*   **Security Tool Containers:** Maintained isolated Docker environments for offensive security tools to prevent cross-contamination between engagements.

### 🤖 Cyber-AutoAgent: Memory-Augmented Recon
**Role:** AI Agent Developer
Developed an autonomous cybersecurity reconnaissance agent with persistent, cross-session memory.
*   **Memory Layer (Mem0):** Integrated `Mem0` as a stateful memory backend, enabling the agent to retain recon findings across sessions.
*   **Local Vector Store (FAISS):** Used FAISS for local, offline embedding storage and similarity search (1024-dim `mxbai-embed-large` embeddings).
*   **Local LLM (Ollama):** Deployed `LLaMA 3.2 (3b)` locally via Ollama for uncensored, private LLM reasoning — configured and debugged `base_url` override issues.
*   **Mission Scope:** Automated subdomain discovery, reconnaissance, and initial access vectoring against target infrastructure.

### 🦠 RAT & C2 Framework Analysis
**Role:** Malware Researcher
Conducted detailed technical analysis of modern Remote Access Trojans (RATs) and C2 frameworks for defensive intelligence.
*   **Frameworks Analyzed:** Remcos RAT, Cobalt Strike, and Sliver C2.
*   **Evasion Techniques:** Studied **Process Injection** and **Process Hollowing** to understand how malware evades signature-based AV/EDR detection.
*   **Persistence Mechanisms:** Analyzed Registry-based persistence techniques (UAC bypass via registry modifications) for reboots.
*   **C2 Infrastructure:** Investigated encrypted communication channels and Distributed DNS (DGA) for resilient, hard-to-block command-and-control.
*   **Phishing Delivery:** Analyzed delivery mechanisms using malicious Office macros and obfuscated `.bat` files for initial access.
*   **IOC Analysis:** Identified Indicators of Compromise (IOCs) and network traffic signatures for defensive countermeasures.

---

## 🔬 Current Focus
I am currently expanding my expertise in integrating Large Language Models (LLMs) and RAG (Retrieval-Augmented Generation) systems into security analysis, while mastering Advanced JavaScript/TypeScript execution environments and scalable PostgreSQL architectures.
