import logging
from datetime import datetime
from typing import Dict, Any, List, TypedDict, Literal

from langgraph.constants import END
from langgraph.graph import StateGraph
# from langgraph.graph.graph import CompiledGraph

from code_analyzer import CodeAnalyzer, CodeIssues, CodeVulnerabilities, CodePerformance
from codeup_client import GitCodeupClient, MergeRequestModal, CodeUpDiffModal

logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    pr_id: str
    pr_info: MergeRequestModal
    diffs: CodeUpDiffModal
    quality_issues: CodeIssues
    vulnerabilities: CodeVulnerabilities
    performance: CodePerformance
    avg_score: int
    approval_status: Literal["APPROVED", "REJECTED", "NEEDS_WORK"]
    suggestions: List[str]
    test_coverage: float


def _extract_files_to_review(diffs: CodeUpDiffModal) -> str:
    code_snippets = ''
    for diff_content in diffs.diffs:
        code_snippets += f"【文件名】\n：{diff_content.new_path} \n"
        code_snippets += f"【代码内容】：\n '''\n {diff_content.diff}  \n'''"
    return code_snippets


class CodeReviewAgent:
    """AI代码审核工作流"""

    def __init__(self, codeup_client: GitCodeupClient, code_analyzer: CodeAnalyzer):
        self.codeup_client = codeup_client
        self.code_analyzer = code_analyzer
        self.workflow = self._create_workflow()

    def _create_workflow(self):
        """创建LangGraph工作流"""
        workflow = StateGraph(AgentState)

        # 定义节点
        workflow.add_node("fetch_pr", self.fetch_pr_node)
        workflow.add_node("analyze_changes", self.analyze_changes_node)
        workflow.add_node("code_quality_check", self.code_quality_check_node)
        workflow.add_node("security_scan", self.security_scan_node)
        workflow.add_node("performance_analysis", self.performance_analysis_node)
        workflow.add_node("generate_report", self.generate_report_node)
        workflow.add_node("post_comments", self.post_comments_node)

        # 定义边
        workflow.add_edge("fetch_pr", "analyze_changes")
        workflow.add_edge("analyze_changes", "code_quality_check")
        workflow.add_edge("code_quality_check", "security_scan")
        workflow.add_edge("security_scan", "performance_analysis")
        workflow.add_edge("performance_analysis", "generate_report")
        workflow.add_edge("generate_report", "post_comments")
        workflow.add_edge("post_comments", END)

        # 设置入口点
        workflow.set_entry_point("fetch_pr")
        return workflow.compile()

    async def fetch_pr_node(self, state: AgentState):
        """获取PR信息节点"""
        logger.info(f"获取PR信息: {state['pr_id']}")
        pr_info = self.codeup_client.get_change_request(state['pr_id'])
        return {"pr_info": pr_info}

    async def analyze_changes_node(self, state: AgentState):
        """分析变更节点"""
        logger.info("分析代码变更")
        pr_changes: MergeRequestModal = state['pr_info']
        pr_diffs = self.codeup_client.diff(pr_changes.source_branch, pr_changes.target_branch)
        return {"diffs": pr_diffs}

    async def code_quality_check_node(self, state: AgentState):
        """代码质量检查节点"""
        logger.info("执行代码质量检查")
        diffs: CodeUpDiffModal = state["diffs"]
        return {"quality_issues": await self.code_analyzer.analyze_code_quality(_extract_files_to_review(diffs))}

    async def security_scan_node(self, state: AgentState):
        """安全扫描节点"""
        logger.info("执行安全扫描")
        diffs: CodeUpDiffModal = state["diffs"]
        return {"vulnerabilities": await self.code_analyzer.detect_security_vulnerabilities(_extract_files_to_review(diffs))}

    async def performance_analysis_node(self, state: Dict[str, Any]):
        """性能分析节点"""
        logger.info("执行性能分析")
        diffs: CodeUpDiffModal = state["diffs"]
        return {"performance": await self.code_analyzer.analyze_performance(_extract_files_to_review(diffs))}

    async def generate_report_node(self, state: AgentState) -> Dict[str, Any]:
        """生成报告节点"""
        logger.info("生成审核报告")
        # 汇总所有分析结果
        quality_issues: CodeIssues = state["quality_issues"]
        code_risks: CodeVulnerabilities = state["vulnerabilities"]
        code_performance: CodePerformance = state["performance"]

        # 计算总体评分
        avg_quality_score = (quality_issues.score + code_risks.score + code_performance.score) / 3

        # 确定审核状态
        critical_issues = len([r for r in code_risks.vulnerabilities if r.severity == 'high'])
        # 如果存在严重风险问题，则拒绝PR
        if critical_issues > 0:
            approval_status = "REJECTED"
        # 如果平均分数小于60分，则认为需要修正
        elif avg_quality_score < 60:
            approval_status = "NEEDS_WORK"
        else:
            approval_status = "APPROVED"

        # 生成建议
        suggestions = self._generate_suggestions(quality_issues, code_risks, code_performance)

        return {
            "approval_status": approval_status,
            "avg_score": int(avg_quality_score),
            "suggestions": suggestions,
            "test_coverage": 0.0,  # 可以集成测试覆盖率工具
        }

    async def post_comments_node(self, state: AgentState):
        """发布评论节点"""
        logger.info("发布审核评论")

        # 生成主评论
        main_comment = self._generate_main_comment(state)

        pr_id = state['pr_id']
        quality_issues: CodeIssues = state['quality_issues']
        vulnerabilities: CodeVulnerabilities = state['vulnerabilities']
        performance_issues: CodePerformance = state['performance']

        # 发布主评论
        self.codeup_client.mr_comment(
            state['pr_id'],
            main_comment
        )

        # 发布具体文件的评论
        for issue in quality_issues.issues:
            print("issue", issue.new_file)
            if issue.line_number:
                if issue.new_file:
                    position = {
                        "position_type": "text",
                        "base_sha": None,  # 会自动填充
                        "start_sha": None,  # 会自动填充
                        "head_sha": None,  # 会自动填充
                        # "old_path": file_path,
                        "new_path": issue.filename,
                        # "old_line": line_number if line_type == "old" else None,
                        "new_line": issue.line_number
                    }
                else:
                    position = {
                        "position_type": "text",
                        "base_sha": None,  # 会自动填充
                        "start_sha": None,  # 会自动填充
                        "head_sha": None,  # 会自动填充
                        "old_path": issue.filename,
                        # "new_path": file_path,
                        "old_line": issue.line_number,
                        # "new_line": line_number if line_type == "new" else None
                    }
                self.codeup_client.mr_comment(
                    pr_id,
                    f"文件名：{issue.filename} \n问题描述：{issue.description} \n行号：{issue.line_number}",
                    position
                )
        # 发布安全风险评论
        for risk in vulnerabilities.vulnerabilities:
            print("risk", risk.new_file)
            if risk.line_number:
                severity_emoji = "🚨" if risk.severity == 'high' else "⚠️"
                if risk.new_file:
                    position = {
                        "position_type": "text",
                        "base_sha": None,  # 会自动填充
                        "start_sha": None,  # 会自动填充
                        "head_sha": None,  # 会自动填充
                        # "old_path": file_path,
                        "new_path": risk.filename,
                        # "old_line": line_number if line_type == "old" else None,
                        "new_line": risk.line_number
                    }
                else:
                    position = {
                        "position_type": "text",
                        "base_sha": None,  # 会自动填充
                        "start_sha": None,  # 会自动填充
                        "head_sha": None,  # 会自动填充
                        "old_path": risk.filename,
                        # "new_path": file_path,
                        "old_line": risk.line_number,
                        # "new_line": line_number if line_type == "new" else None
                    }
                self.codeup_client.mr_comment(
                    pr_id,
                    f"{severity_emoji} 安全风险：{risk.description} \n文件名：{risk.filename} \n行号：{risk.line_number}",
                    position
                )
        for performance in performance_issues.performance_issues:
            print("performance", performance.new_file)
            if performance.line_number:
                if performance.new_file:
                    position = {
                        "position_type": "text",
                        "base_sha": None,  # 会自动填充
                        "start_sha": None,  # 会自动填充
                        "head_sha": None,  # 会自动填充
                        # "old_path": file_path,
                        "new_path": performance.filename,
                        # "old_line": line_number if line_type == "old" else None,
                        "new_line": performance.line_number
                    }
                else:
                    position = {
                        "position_type": "text",
                        "base_sha": None,  # 会自动填充
                        "start_sha": None,  # 会自动填充
                        "head_sha": None,  # 会自动填充
                        "old_path": performance.filename,
                        # "new_path": file_path,
                        "old_line": performance.line_number,
                        # "new_line": line_number if line_type == "new" else None
                    }
                self.codeup_client.mr_comment(
                    pr_id,
                    f"性能问题：{performance.description} \n文件名：{performance.filename} \n行号：{performance.line_number}",
                    position
                )

        return state

    def _should_review_file(self, file_path: str) -> bool:
        """判断是否需要审核文件"""
        # 排除不需要审核的文件
        exclude_patterns = [
            '.git/',
            'node_modules/',
            '.DS_Store',
            '*.log',
            '*.tmp',
            '*.cache'
        ]

        for pattern in exclude_patterns:
            if pattern in file_path:
                return False

        # 只审核代码文件
        code_extensions = ['.py', '.js']
        return any(file_path.endswith(ext) for ext in code_extensions)

    def _generate_suggestions(self, quality_issues: CodeIssues, code_risks: CodeVulnerabilities, code_performance: CodePerformance) -> List[str]:
        """生成改进建议"""
        suggestions = []
        if quality_issues.issues:
            suggestions.append("建议优化代码质量，提高可读性和维护性")

        if code_risks.vulnerabilities:
            high_risk_count = len([r for r in code_risks.vulnerabilities if r.severity == 'high'])
            if high_risk_count > 0:
                suggestions.append(f"发现{high_risk_count}个高风险安全问题，建议立即修复")

        if code_performance.performance_issues:
            suggestions.append("建议优化性能相关代码，提高执行效率")

        return suggestions

    def _generate_main_comment(self, state: AgentState) -> str:
        """生成主评论"""
        status_emoji = {
            "APPROVED": "✅",
            "NEEDS_WORK": "⚠️",
            "REJECTED": "❌"
        }

        approval_status = state['approval_status']
        score = state['avg_score']
        quality_issues: CodeIssues = state['quality_issues']
        vulnerabilities: CodeVulnerabilities = state['vulnerabilities']
        performance: CodePerformance = state['performance']
        suggestions = state['suggestions']
        emoji = status_emoji.get(approval_status, "ℹ️")

        comment = f"""
                ## {emoji} AI代码审核报告
            
                **审核状态**: {approval_status}  
                **总体评分**: {score}/100  
            
                ### 📊 审核统计
                - 质量问题: {len(quality_issues.issues)}个
                - 安全风险: {len(vulnerabilities.vulnerabilities)}个
                - 性能问题: {len(performance.performance_issues)}个
            
                ### 🔍 主要问题
                """
        # 添加主要问题
        for i, issue in enumerate(quality_issues.issues[:5]):  # 只显示前5个问题
            comment += f"{i + 1}. **{issue.filename}**: {issue.description}\n"

        if len(quality_issues.issues) > 5:
            comment += f"...还有{len(quality_issues.issues) - 5}个问题，请查看详细评论\n"

        # 添加安全风险
        if vulnerabilities.vulnerabilities:
            comment += "\n### 🚨 安全风险\n"
            for risk in vulnerabilities.vulnerabilities[:5]:
                comment += f"- **{risk.filename}**: {risk.description} (严重程度: {risk.severity})\n"

        # 添加改进建议
        if suggestions:
            comment += "\n### 💡 改进建议\n"
            for suggestion in suggestions:
                comment += f"- {suggestion}\n"

        comment += f"\n---\n*本报告由AI代码审核系统生成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"

        return comment
