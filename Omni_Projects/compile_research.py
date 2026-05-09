import os
import glob

# Paths
INPUT_DIR = r"D:\chatgpt_data_gokul\Technical_Chats_Export"
BASE_PROJ_DIR = r"c:\Users\sk rafi\Downloads\red team Anti\Omni_Projects"

PROJ_AVIATOR = os.path.join(BASE_PROJ_DIR, "Aviator_Predictor")
PROJ_LLM = os.path.join(BASE_PROJ_DIR, "LLM_Deployments")
PROJ_CYBER = os.path.join(BASE_PROJ_DIR, "Cyber_Security_Tools")

# Keywords for categorization
KW_AVIATOR = ["aviator", "crash", "prediction", "gambling", "hash", "serverseed", "1xbet"]
KW_LLM = ["llm", "train", "model", "prompt", "gpt", "h2o", "uncensored", "deploy", "agent", "kaggle", "machine learning"]
KW_CYBER = ["cyber", "security", "vulnerability", "cve", "wireshark", "nettacker", "caldera", "recon", "nmap", "xss", "sqli", "penetration", "metasploit", "kali"]

def categorize(text):
    text_lower = text.lower()
    
    score_aviator = sum(1 for kw in KW_AVIATOR if kw in text_lower)
    score_llm = sum(1 for kw in KW_LLM if kw in text_lower)
    score_cyber = sum(1 for kw in KW_CYBER if kw in text_lower)
    
    # Return the category with the highest score, if > 0
    scores = {"Aviator": score_aviator, "LLM": score_llm, "Cyber": score_cyber}
    best_cat = max(scores, key=scores.get)
    
    if scores[best_cat] > 0:
        return best_cat
    return "Misc"

def main():
    md_files = glob.glob(os.path.join(INPUT_DIR, "*.md"))
    
    aviator_chats = []
    llm_chats = []
    cyber_chats = []
    
    for fp in md_files:
        with open(fp, 'r', encoding='utf-8') as f:
            content = f.read()
            
        cat = categorize(content)
        
        # We only store the filename and the actual content
        chat_data = f"\n\n{'='*60}\nSource File: {os.path.basename(fp)}\n{'='*60}\n\n{content}\n"
        
        if cat == "Aviator":
            aviator_chats.append(chat_data)
        elif cat == "LLM":
            llm_chats.append(chat_data)
        elif cat == "Cyber":
            cyber_chats.append(chat_data)
            
    # Write compiled files
    with open(os.path.join(PROJ_AVIATOR, "COMPILED_RESEARCH.md"), 'w', encoding='utf-8') as f:
        f.write("# Compiled Aviator Research & Experiments\n")
        f.write("This document contains all historical chats related to the Aviator project.\n")
        f.writelines(aviator_chats)
        
    with open(os.path.join(PROJ_LLM, "COMPILED_RESEARCH.md"), 'w', encoding='utf-8') as f:
        f.write("# Compiled LLM & ML Research\n")
        f.write("This document contains all historical chats related to LLM deployment and ML modeling.\n")
        f.writelines(llm_chats)
        
    with open(os.path.join(PROJ_CYBER, "COMPILED_RESEARCH.md"), 'w', encoding='utf-8') as f:
        f.write("# Compiled Cyber Security Research\n")
        f.write("This document contains all historical chats related to Red Teaming, tools, and vulnerabilities.\n")
        f.writelines(cyber_chats)
        
    print(f"Compilation Complete!")
    print(f"Aviator Chats: {len(aviator_chats)}")
    print(f"LLM Chats: {len(llm_chats)}")
    print(f"Cyber Chats: {len(cyber_chats)}")

if __name__ == "__main__":
    main()
