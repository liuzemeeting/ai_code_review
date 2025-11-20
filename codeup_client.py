from __future__ import annotations

import os
from typing import List

import requests
from pydantic import BaseModel



class AuthorModal(BaseModel):
    """
    Codeup变更请求作者模型
    """
    avatar_url: str
    web_url: str
    id: int
    name: str
    state: str
    username: str


class MergeRequestModal(BaseModel):
    """
    Codeup变更请求模型
    """
    author: AuthorModal
    source_branch: str
    project_id: int
    target_branch: str
    merge_status: str
    title: str
    web_url: str
    updated_at: str
    project_id: int


class Comment(BaseModel):
    """
    Codeup变更请求评论模型
    """
    author_email: str
    author_name: str
    authored_date: str
    committed_date: str
    committer_email: str
    committer_name: str
    id: str
    message: str
    parent_ids: list
    short_id: str
    title: str


class Diff(BaseModel):
    """
    diff模型
    """
    a_mode: str
    b_mode: str
    deleted_file: bool
    diff: str
    new_file: bool
    new_path: str
    old_path: str
    renamed_file: bool


class CodeUpDiffModal(BaseModel):
    commits: List[Comment]
    diffs: List[Diff]


project_token = {
    "project_id": "project_token",
}
git_host = "https://gitlab.com"

class GitCodeupClient:

    def __init__(self, project_id):
        self.headers = {
            "PRIVATE-TOKEN": project_token[project_id],
            "Content-Type": "application/json"
        }
        self.org_id = os.getenv('ORG_ID')
        self.project_id = project_id

    def __codeup_request(self, url, method='GET', data=None):
        """通用的Codeup请求方法"""
        response = requests.request(method, url, headers=self.headers, json=data)
        print(response.json())
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()
        return None

    def get_change_request(self, local_id: str) -> MergeRequestModal:
        """获取变更请求"""
        url = f'{git_host}/api/v4/projects/{self.project_id}/merge_requests/{local_id}'
        return MergeRequestModal(**self.__codeup_request(url))

    def diff(self, source_branch: str, target_branch: str) -> CodeUpDiffModal:
        url = f"{git_host}/api/v4/projects/{self.project_id}/repository/compare?from={target_branch}&to={source_branch}&straight={False}"
        return CodeUpDiffModal(**self.__codeup_request(url))

    def mr_comment(self, local_id: str, content: str, position: dict = None):
        url = f'{git_host}/api/v4/projects/{self.project_id}/merge_requests/{local_id}/notes'

        data = {
            "body": content,
        }
        if position:
            data['position'] = position
        print('data', data)
        return self.__codeup_request(url, method='POST', data=data)


if __name__ == '__main__':
    client = GitCodeupClient('240')
    try:
        change_request = client.get_change_request("1")
        print(change_request)
        print(change_request.source_branch)
        print(change_request.target_branch)
        diffs = client.diff(change_request.source_branch, "master")
        print(diffs)
        client.mr_comment("1", "这是一个测试评论")

    except requests.HTTPError as e:
        print(f"Error fetching change request: {e}")
