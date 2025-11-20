import logging
from typing import Literal

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from code_analyzer import CodeAnalyzer
from code_review_agent import CodeReviewAgent
from codeup_client import GitCodeupClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

analyzer = CodeAnalyzer()

app = FastAPI(
    title="Code Review API",
    description="An API to trigger code reviews for Pull Requests.",
    version="1.0.0",
)


@app.get("/mr-manully/review/{pr_id}", tags=["Code Review"])
async def run_review_endpoint(pr_id: str):
    """
    Triggers a code review process for a given Pull Request ID.
    """
    logger.info(f"Received request to review PR ID: {pr_id}")
    await run(pr_id, "240")


class MergeRequestEvent(BaseModel):
    iid: int
    state: Literal["opened", "close", "reopen"]
    project_id: str


class MrWebhookModal(BaseModel):
    """Webhook for Merge Request"""
    object_attributes: MergeRequestEvent


@app.post("/mr/review", tags=["Code Review WebHook"])
async def run_review_endpoint(data: MrWebhookModal):
    if isinstance(data, MrWebhookModal):
        if data.object_attributes.state == "opened":
            iid = data.object_attributes.iid
            project_id = data.object_attributes.project_id
            print(iid)
            await run(str(iid), project_id)


async def run(pr_id: str, project_id: str):
    codeup_client = GitCodeupClient(project_id)
    agent = CodeReviewAgent(codeup_client, analyzer)
    state = await agent.workflow.ainvoke(
        {
            "pr_id": pr_id,
        }
    )
    logger.info(f"State for PR {pr_id}: {state}")
    return state


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8888)
