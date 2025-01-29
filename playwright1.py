import asyncio
from typing import Annotated
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from playwright.async_api import async_playwright


class State(TypedDict):
    messages: Annotated[list, add_messages]

graph_builder = StateGraph(State)

async def fetch_postMessage_listeners(state: State):
    """Uses CDP to fetch all postMessage event listeners from a website."""
    url = state["messages"][-1]["content"]
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False) 
        context = await browser.new_context()
        page = await context.new_page()

        client = await context.new_cdp_session(page)

        await page.goto(url)

        listeners = await page.evaluate("""
            (() => {
                return (window.getEventListeners(window).message || []).map(l => l.listener.toString());
            })();
        """)

        await browser.close()
    
    return {"messages": [{"role": "system", "content": "Extracted Listeners"}, {"role": "data", "content": listeners}]}

async def analyze_security_risks(state: State):
    """AI analyzes the event listeners for potential security risks."""
    listeners = state["messages"][-1]["content"]
    
    risk_analysis = []
    for listener in listeners:
        if "eval(" in listener or "innerHTML" in listener:
            risk_analysis.append(f"Potential XSS risk found: {listener[:100]}...")
    
    return {"messages": [{"role": "system", "content": "Security Analysis"}, {"role": "data", "content": risk_analysis}]}

graph_builder.add_node("fetch_listeners", fetch_postMessage_listeners)
graph_builder.add_node("analyze_risks", analyze_security_risks)

graph_builder.add_edge(START, "fetch_listeners")
graph_builder.add_edge("fetch_listeners", "analyze_risks")
graph_builder.add_edge("analyze_risks", END)

graph = graph_builder.compile()

async def main():
    url = input("Enter website URL: ")
    async for event in graph.astream({"messages": [{"role": "user", "content": url}]}):
        for value in event.values():
            print(value["messages"][-1]["content"]) 

asyncio.run(main())
