import os
from typing import List, Literal

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field


class QualityIssue(BaseModel):
    """代码问题模型"""
    new_file: bool = Field(description="是否为新增文件")
    filename: str = Field(description="文件名")
    description: str = Field(description="代码质量问题描述")
    line_number: int = Field(description="代码行号")


class CodeIssues(BaseModel):
    """代码分析结果模型"""
    score: int = Field(description="代码评分分值，范围从0到100", default=0)
    issues: List[QualityIssue] = Field(description="代码中存在的issue列表")


class Vulnerability(BaseModel):
    """安全漏洞模型"""
    filename: str = Field(description="文件名")
    new_file: bool = Field(description="是否为新增文件")
    type: str = Field(description="漏洞类型")
    severity: Literal["low", "medium", "high"] = Field(description="漏洞严重性，可选值有 low, medium, high")
    description: str = Field(description="漏洞描述")
    line_number: int = Field(description="代码行号")


class CodeVulnerabilities(BaseModel):
    """代码安全漏洞模型"""
    score: int = Field(description="代码评分分值，范围从0到100", default=0)
    vulnerabilities: List[Vulnerability] = Field(description="代码中的安全漏洞列表")


class PerformanceIssue(BaseModel):
    filename: str = Field(description="文件名")
    new_file: bool = Field(description="是否为新增文件")
    description: str = Field(description="性能问题描述")
    line_number: int = Field(description="代码行号")


class CodePerformance(BaseModel):
    """代码性能分析结果模型"""
    filename: str = Field(description="文件名")
    performance_issues: List[PerformanceIssue] = Field(description="代码中的性能问题列表")
    score: int = Field(description="整体性能评分，范围从0到100")


class CodeAnalyzer:
    """代码分析器"""

    def __init__(self):
        self.llm = ChatOpenAI(
            api_key='', # 请替换为您的DashScope API Key 申请地址：https://bailian.console.aliyun.com/
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            model="qwen-max",
            temperature=0.2,
            verbose=True,
        )

    async def analyze_code_quality(self, code: str) -> CodeIssues:
        """分析代码质量"""
        prompt = ChatPromptTemplate.from_template("""
        以下是一份git diff的代码内容，请分析以下代码的质量

        代码内容:
        ```
        {code}
        ```
        请从以下维度进行分析：
        1. 代码规范性
        2. 可读性
        3. 复杂度
        4. 命名规范
        5. 注释质量

        返回JSON格式结果，包含score(0-100)和issues列表以及问题所在的filename。
        """)
        chain = prompt | self.llm.with_structured_output(CodeIssues, method="function_calling")
        return await chain.ainvoke(input={"code": code})

    async def detect_security_vulnerabilities(self, code: str) -> CodeVulnerabilities:
        """检测安全漏洞"""
        prompt = ChatPromptTemplate.from_template("""
        以下是一份git diff的代码内容，请检测以下代码中的安全漏洞

        代码内容:
        ```
        {code}
        ```

        重点检查：
        1. SQL注入
        2. XSS攻击
        3. CSRF攻击
        4. 敏感信息泄露
        5. 不安全的加密
        6. 权限控制问题

        返回JSON格式，包含vulnerabilities列表，每项包含filename、 type、severity、description、line_number。
        """)

        chain = prompt | self.llm.with_structured_output(CodeVulnerabilities, method="function_calling")
        return await chain.ainvoke(input={"code": code})

    async def analyze_performance(self, code: str) -> CodePerformance:
        """性能分析"""
        prompt = ChatPromptTemplate.from_template("""
        以下是一份git diff的代码内容，请分析以下代码的性能问题

        代码内容:
        ```
        {code}
        ```

        检查要点：
        1. 算法复杂度
        2. 内存使用
        3. 数据库查询优化
        4. 循环优化
        5. 缓存使用

        返回JSON格式，包含问题所在的filename，performance_issues、score。
        """)
        chain = prompt | self.llm.with_structured_output(CodePerformance, method="function_calling")
        return await chain.ainvoke(input={"code": code})
