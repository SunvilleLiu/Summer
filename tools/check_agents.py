#!/usr/bin/env python3
"""AI 作业规范机检。

校验 AGENTS.md 与 PROGRESS.md 本身的可用性——与 check_docs.py 关注的对象不同：
check_docs.py 按文档手册规则校验 docs/ 六卷，本脚本校验作业规范与进度文件。

用法：
    python3 tools/check_agents.py
    python3 tools/check_agents.py --quiet

退出码：0 = 无 ERROR（WARN 不阻断）；1 = 存在 ERROR。
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ROOT / "AGENTS.md"
CLAUDE = ROOT / "CLAUDE.md"
PROGRESS = ROOT / "PROGRESS.md"
DOCS = ROOT / "docs"

# AGENTS.md 中引用文档章节的两种写法：
#   `docs/03-交付治理与上线.md` §1.2
#   `03` §5.1        —— 表格内的简写，卷号需能唯一定位到一卷
POINTER_RE = re.compile(r"`(?:docs/)?(\d{2})[^`]*`\s*§(\d+(?:\.\d+)*)")
HEADING_NUM_RE = re.compile(r"^#{2,5}\s+(\d+(?:\.\d+)*)\.?\s")

# 进度表：| 任务 | 状态 | 验证命令 | 分支 |
STATUSES = {"未开始", "进行中", "已完成", "阻塞"}
PLACEHOLDERS = {"", "—", "-", "–", "待定", "TBD", "无"}

# AGENTS.md §11：涉及代码的条目，验证命令必须包含测试执行。
# 按命令内容判定而非新增「类型」列——不改表结构，无需人工分类，无歧义。
BUILD_CMDS = ("dotnet build", "dotnet publish", "npm run build", "yarn build")
TEST_CMDS = ("dotnet test", "npm test", "npm run test", "pytest", "vitest")


class Report:
    def __init__(self) -> None:
        self.items: list[tuple[str, str, str]] = []
        self.stats: list[tuple[str, str]] = []

    def error(self, check: str, msg: str) -> None:
        self.items.append(("ERROR", check, msg))

    def warn(self, check: str, msg: str) -> None:
        self.items.append(("WARN", check, msg))

    def stat(self, label: str, value: str) -> None:
        self.stats.append((label, value))

    @property
    def errors(self) -> int:
        return sum(1 for lvl, _, _ in self.items if lvl == "ERROR")

    @property
    def warnings(self) -> int:
        return sum(1 for lvl, _, _ in self.items if lvl == "WARN")


def volume_sections() -> dict[str, set[str]]:
    """返回 {卷号: 该卷全部章节号}。"""
    out: dict[str, set[str]] = {}
    for path in sorted(DOCS.glob("0[0-5]*.md")):
        nums = set()
        fence = False
        for line in path.read_text(encoding="utf-8").split("\n"):
            if line.lstrip().startswith("```"):
                fence = not fence
                continue
            if fence:
                continue
            m = HEADING_NUM_RE.match(line)
            if m:
                nums.add(m.group(1))
        out[path.name[:2]] = nums
    return out


def parse_rows(text: str, header_contains: str) -> list[list[str]]:
    """取出表头包含指定字样的 Markdown 表格的数据行。"""
    rows: list[list[str]] = []
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if not (line.startswith("|") and header_contains in line):
            continue
        if i + 1 >= len(lines) or not re.match(r"^\|[\s:|-]+\|$", lines[i + 1]):
            continue
        for row in lines[i + 2:]:
            if not row.startswith("|"):
                break
            rows.append([c.strip() for c in row.strip("|").split("|")])
    return rows


# --- 检查项 ---------------------------------------------------------------

def check_files_exist(rep: Report) -> None:
    for path in (AGENTS, CLAUDE, PROGRESS):
        if not path.exists():
            rep.error("文件", f"缺少 {path.name}")


def check_pointers(rep: Report) -> None:
    """AGENTS.md 引用的卷与章节号必须真实存在。

    各卷刚做过全卷重编号，指针失效是已验证的真实风险。
    """
    if not AGENTS.exists():
        return
    sections = volume_sections()
    text = AGENTS.read_text(encoding="utf-8")
    total = 0
    for m in POINTER_RE.finditer(text):
        vol, num = m.group(1), m.group(2)
        total += 1
        if vol not in sections:
            rep.error("指针", f"AGENTS.md 引用了不存在的卷 {vol}")
        elif num not in sections[vol]:
            rep.error("指针", f"AGENTS.md 引用的 {vol} 卷 §{num} 不存在")
    rep.stat("章节指针", f"{total} 个，全部可解析" if not rep.errors else str(total))
    if total == 0:
        rep.warn("指针", "AGENTS.md 未引用任何文档章节，权威出处可能缺失")


def check_claude_pointer(rep: Report) -> None:
    """CLAUDE.md 只应指向 AGENTS.md，不得复制规则内容。"""
    if not CLAUDE.exists():
        return
    text = CLAUDE.read_text(encoding="utf-8")
    if "AGENTS.md" not in text:
        rep.error("指针", "CLAUDE.md 未指向 AGENTS.md")
    if len(text.split("\n")) > 20:
        rep.warn("指针", "CLAUDE.md 超过 20 行，可能已开始复制 AGENTS.md 的内容；"
                        "同一规则两处存放必然漂移")


def check_progress(rep: Report) -> None:
    """进度文件：状态取值合法，且「已完成」必须配可执行验证命令。"""
    if not PROGRESS.exists():
        return
    rows = parse_rows(PROGRESS.read_text(encoding="utf-8"), "验证命令")
    if not rows:
        rep.error("进度", "PROGRESS.md 找不到含「验证命令」列的任务表")
        return

    counts: dict[str, int] = {}
    for row in rows:
        if len(row) < 3:
            rep.error("进度", f"任务行列数不足：{row}")
            continue
        task, status, verify = row[0], row[1], row[2]
        if status not in STATUSES:
            rep.error("进度", f"「{task}」状态 '{status}' 非法，"
                            f"合法取值：{'/'.join(sorted(STATUSES))}")
            continue
        counts[status] = counts.get(status, 0) + 1
        if status != "已完成":
            continue
        # 去掉 Markdown 反引号后判断是否为占位符
        cmd = verify.strip().strip("`").strip()
        if cmd in PLACEHOLDERS:
            rep.error("进度", f"「{task}」标记为已完成但无验证命令；"
                            f"没有可执行验证的条目不得标记完成")
            continue
        # 构建通过只说明语法正确，不说明行为正确
        if (any(b in cmd for b in BUILD_CMDS)
                and not any(t in cmd for t in TEST_CMDS)):
            rep.error("进度", f"「{task}」的验证命令只有构建没有测试；"
                            f"构建通过不等于完成，须包含测试执行（AGENTS.md §11）")

    rep.stat("任务", "，".join(f"{k} {v}" for k, v in sorted(counts.items())))


CHECKS = [
    ("规范文件存在", check_files_exist),
    ("AGENTS.md 章节指针", check_pointers),
    ("CLAUDE.md 指针", check_claude_pointer),
    ("PROGRESS.md 进度表", check_progress),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="AI 作业规范机检")
    parser.add_argument("--quiet", action="store_true", help="只输出失败项与总结")
    args = parser.parse_args()

    rep = Report()
    for label, fn in CHECKS:
        before = len(rep.items)
        fn(rep)
        if not args.quiet:
            new = rep.items[before:]
            mark = "FAIL" if any(l == "ERROR" for l, _, _ in new) else "ok"
            print(f"[{mark:>4}] {label}")

    if rep.stats and not args.quiet:
        print("\n指标：")
        for label, value in rep.stats:
            print(f"  {label}: {value}")

    if rep.items:
        print("\n明细：")
        for level, check, msg in rep.items:
            print(f"  {level:5} [{check}] {msg}")

    print(f"\n结果：{rep.errors} 个 ERROR，{rep.warnings} 个 WARN")
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
