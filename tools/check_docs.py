#!/usr/bin/env python3
"""财税服务协作 SaaS 文档基线机检。

按 docs/00-文档手册.md 的独立性规则、稳定标识约定和基线限制校验 docs/ 下的
文档基线，并统计需求覆盖率与可评审性指标。

用法：
    python3 tools/check_docs.py            # 全部检查
    python3 tools/check_docs.py --quiet    # 只输出失败项与总结

退出码：0 = 无 ERROR（WARN 不阻断）；1 = 存在 ERROR。
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"
SEED = DOCS / "04附件-权限审批种子.json"

# 手册第 3 节登记的稳定标识前缀；其余大写短横线串（错误码等）不受归属规则约束。
HANDBOOK_PREFIXES = {
    "BR", "FR", "NFR", "DEC", "DOM", "ENT", "PAGE", "API", "EVT",
    "STATE", "CALC", "TEST", "MIG", "INV", "SOD", "RISK", "GATE",
}

# 手册第 3 条：基座卷定义的公共词汇，全体卷可直接使用，不构成引用。
SHARED_PREFIXES = {"DOM", "INV", "GATE", "FR", "NFR", "PAGE", "TEST", "MIG", "DEC", "RISK"}
SHARED_IDS = {"SOD-CONFLICT-001"}  # 基座卷定义的通用职责冲突守卫

# 已知且经裁定保留的跨卷标识。键为标识，值为保留理由。
# 这些项以 WARN 形式每次可见，不阻断；裁定改变时从此处移除。
ALLOWED_CROSS_VOLUME = {
    f"STATE-{s}": "02《软件需求规格》2.6 以「最低状态集合」形式提出状态机需求下限，"
                  "非设计定义；是否改为 02 自有需求标识待 OWNER 裁定"
    for s in ("ORG-001", "ORG-002", "WSP-001", "WSP-002", "CTR-001", "SVC-001",
              "ACC-001", "ACC-002", "TAX-001", "TAX-002", "COL-001", "COL-002",
              "BILL-001")
}

# 经裁定保留的编号断档：补号会掩盖迁移轨迹或使标题与稳定标识错位。
KNOWN_GAPS = {
    ("04-系统设计.md", "2", 12): "CommercialBilling 领域已移至商业计费卷",
    ("04-系统设计.md", "3", 12): "计费状态机已移至商业计费卷",
    ("04-系统设计.md", "5", 14): "CommercialBilling 数据已移至商业计费卷",
    ("04-系统设计.md", "5.4", 9): "对应已废弃且全库无引用的 ENT-WSP-009",
}

# 棘轮基线：这些数字只允许向好的方向变化，防止回归。
BASELINE = {
    "fr_referenced": 0,       # 被设计/测试卷显式引用的 FR 条数，只增不减
    "nfr_referenced": 16,     # 同上，NFR
    "long_cells": 15,         # 超过 300 字符的表格单元格数，只减不增
}
LONG_CELL_CHARS = 300

ID_RE = re.compile(r"\b([A-Z]+)-([A-Z0-9]+)-(\d+)\b")
HEADING_RE = re.compile(r"^(#{2,5}) (.+)$")
NUM_RE = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+(.*)$")
PERM_RE = re.compile(r"`([a-z][a-z0-9_]*\.[a-z0-9_]+(?:\.[a-z0-9_]+)+)`")
SOD_RE = re.compile(r"SOD-[A-Z]+-\d+")
FR_RE = re.compile(r"\bFR-[A-Z]+-\d+")   # \b 必须保留：否则会匹配 NFR-SEC-001 的尾部
NFR_RE = re.compile(r"\bNFR-[A-Z]+-\d+")


class Report:
    def __init__(self) -> None:
        self.items: list[tuple[str, str, str]] = []  # (level, check, message)
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


def volumes() -> dict[str, str]:
    """返回 {文件名: 正文}，按卷号排序。"""
    return {p.name: p.read_text(encoding="utf-8")
            for p in sorted(DOCS.glob("0[0-5]*.md"))}


def headings(text: str):
    """产出 (level, title)，跳过代码围栏内的内容。"""
    fence = False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        m = HEADING_RE.match(line)
        if m:
            yield len(m.group(1)), m.group(2)


# --- 检查项 ---------------------------------------------------------------

def check_identifier_ownership(vols: dict[str, str], rep: Report) -> None:
    """手册 1/4：非公共词汇的稳定标识只能出现在定义它的一卷。"""
    where: dict[str, set[str]] = collections.defaultdict(set)
    for name, text in vols.items():
        for prefix, subject, num in set(ID_RE.findall(text)):
            if prefix not in HANDBOOK_PREFIXES:
                continue  # 错误码等非手册标识
            where[f"{prefix}-{subject}-{num}"].add(name[:2])

    leaked = 0
    for ident, vs in sorted(where.items()):
        if len(vs) < 2:
            continue
        if ident.split("-")[0] in SHARED_PREFIXES or ident in SHARED_IDS:
            continue
        if ident in ALLOWED_CROSS_VOLUME:
            rep.warn("标识归属", f"{ident} 出现于卷 {'/'.join(sorted(vs))}"
                                 f"（已裁定保留：{ALLOWED_CROSS_VOLUME[ident]}）")
            continue
        rep.error("标识归属", f"{ident} 同时出现于卷 {'/'.join(sorted(vs))}，"
                              f"违反卷间零引用")
        leaked += 1
    rep.stat("稳定标识总数", str(len(where)))
    rep.stat("跨卷泄漏", "0" if not leaked else str(leaked))


def check_stale_references(vols: dict[str, str], rep: Report) -> None:
    """手册 1：不得出现其他卷的文件名、编号或章节指向。"""
    patterns = [
        (re.compile(r"《\d{2}-"), "书名号内的旧编号文档引用"),
        (re.compile(r"0[0-5]-[^\s|`]*\.md"), "其他卷文件名"),
        (re.compile(r"(?:采用|见|按|参见)\s*0[0-9]\s"), "裸卷号引用"),
        (re.compile(r"(?<![\d.])0[0-9]/0[0-9](?![\d.])"), "斜杠卷号引用"),
    ]
    for name, text in vols.items():
        for i, line in enumerate(text.split("\n"), 1):
            for pat, desc in patterns:
                if name == "00-文档手册.md" and desc == "其他卷文件名":
                    continue  # 手册的卷结构表本身必须列出卷名
                if pat.search(line):
                    rep.error("旧引用", f"{name}:{i} {desc}：{line.strip()[:70]}")


def check_volume_local_refs(vols: dict[str, str], rep: Report) -> None:
    """手册 1：《》引用必须是卷内引用且章节名可解析。"""
    titles = {
        name: {NUM_RE.sub(r"\2", t).strip() if NUM_RE.match(t) else t.strip()
               for _, t in headings(text)}
        for name, text in vols.items()
    }
    for name, text in vols.items():
        for m in re.finditer(r"(.{0,6})《([^》]+)》", text):
            prefix, target = m.group(1), m.group(2)
            if target == "章节":
                continue  # 手册中的示例写法
            if "本卷" not in prefix:
                rep.error("卷内引用", f"{name}：《{target}》缺「本卷」前缀")
            elif "附件" not in prefix and not any(
                    h.startswith(target) for h in titles[name]):
                rep.error("卷内引用", f"{name}：《{target}》在本卷找不到对应章节")


def check_seed(vols: dict[str, str], rep: Report) -> None:
    """手册 7：权限审批种子是权限/角色/SoD/审批模板的唯一可机检目录。"""
    try:
        seed = json.loads(SEED.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        rep.error("种子", f"无法解析 {SEED.name}：{exc}")
        return

    perms = {p["code"] for p in seed["permissions"]}
    roles = {r["code"] for r in seed["roles"]}
    sods = {s["code"] for s in seed["sodPolicies"]}

    for rp in seed["rolePermissions"]:
        role = rp.get("role") or rp.get("roleCode")
        if role not in roles:
            rep.error("种子", f"rolePermissions 引用未定义角色 {role}")
        for code in rp.get("allow", []) + rp.get("permissions", []):
            if code not in perms:
                rep.error("种子", f"角色 {role} 引用未定义权限 {code}")

    body = "".join(vols[n] for n in vols if n[:2] in {"03", "04", "05"})
    doc_perms = set(PERM_RE.findall(body))
    for code in sorted(doc_perms - perms):
        rep.error("种子", f"文档引用的权限码 {code} 未在种子中定义")

    doc_sods = set()
    for text in vols.values():
        doc_sods |= set(SOD_RE.findall(text))
    for code in sorted(doc_sods - sods):
        rep.error("种子", f"文档引用的 SoD 策略 {code} 未在种子中定义")
    for code in sorted(sods - doc_sods):
        rep.warn("种子", f"种子定义的 {code} 未被任何文档引用")

    rep.stat("权限码", f"种子 {len(perms)} / 文档引用 {len(doc_perms)}")
    rep.stat("SoD 策略", f"种子 {len(sods)} / 文档引用 {len(doc_sods)}")
    rep.stat("角色", str(len(roles)))


def check_numbering(vols: dict[str, str], rep: Report) -> None:
    """章节编号必须层级连续、带章前缀、无重号、父节点齐全。"""
    for name, text in vols.items():
        if name.startswith("00"):
            continue  # 手册篇幅短，不做层级编号
        chapter = 0
        seen: set[str] = set()
        children: dict[str, list[int]] = collections.defaultdict(list)
        for level, title in headings(text):
            m = NUM_RE.match(title)
            if not m:
                rep.error("编号", f"{name}：标题缺编号「{title[:40]}」")
                continue
            num = m.group(1)
            segs = num.split(".")
            if level == 2:
                chapter += 1
                if num != str(chapter):
                    rep.error("编号", f"{name}：章号应为 {chapter}，实为 {num}")
            else:
                if segs[0] != str(chapter):
                    rep.error("编号", f"{name}：{num} 章前缀应为 {chapter}")
                if level == 3 and len(segs) != 2:
                    rep.error("编号", f"{name}：三级标题 {num} 应为两段")
                parent = ".".join(segs[:-1])
                if len(segs) > 2 and parent not in seen:
                    rep.error("编号", f"{name}：{num} 的父节点 {parent} 不存在")
                children[parent].append(int(segs[-1]))
            if num in seen:
                rep.error("编号", f"{name}：编号 {num} 重复")
            seen.add(num)

        for parent, nums in children.items():
            for missing in (n for n in range(1, max(nums) + 1) if n not in nums):
                reason = KNOWN_GAPS.get((name, parent, missing))
                if reason:
                    rep.warn("编号", f"{name}：{parent}.{missing} 断档（已裁定保留：{reason}）")
                else:
                    rep.error("编号", f"{name}：{parent}.{missing} 编号断档")


def check_format(vols: dict[str, str], rep: Report) -> None:
    """合卷痕迹与 Markdown 结构。"""
    for name, text in vols.items():
        lines = text.split("\n")
        for i, line in enumerate(lines, 1):
            if "。。" in line:
                rep.error("格式", f"{name}:{i} 重复句号")
        if re.search(r"\n{3,}", text):
            rep.error("格式", f"{name} 存在连续空行")
        for i in range(len(lines) - 1):
            if lines[i].startswith("## ") and lines[i + 1].startswith("## "):
                rep.error("格式", f"{name}:{i+1} 相邻重复二级标题")
        # 表格列数一致性
        for i, line in enumerate(lines):
            if (line.startswith("|") and i + 1 < len(lines)
                    and re.match(r"^\|[\s:|-]+\|$", lines[i + 1])):
                width = line.count("|")
                j = i + 2
                while j < len(lines) and lines[j].startswith("|"):
                    if lines[j].count("|") != width:
                        rep.error("格式", f"{name}:{j+1} 表格列数与表头不一致")
                    j += 1


def check_coverage(vols: dict[str, str], rep: Report) -> None:
    """需求覆盖率棘轮：被设计/测试卷引用的 FR 条数只增不减。"""
    req = vols["02-产品需求与页面.md"]
    downstream_text = "".join(t for n, t in vols.items() if n[:2] in {"03", "04", "05"})

    for label, pattern, key in (("FR", FR_RE, "fr_referenced"),
                                ("NFR", NFR_RE, "nfr_referenced")):
        defined = set(pattern.findall(req))
        covered = defined & set(pattern.findall(downstream_text))
        pct = 100.0 * len(covered) / len(defined) if defined else 0.0
        rep.stat(f"{label} 覆盖率", f"{len(covered)}/{len(defined)} ({pct:.1f}%)")

        base = BASELINE[key]
        if len(covered) < base:
            rep.error("覆盖率", f"被下游引用的 {label} 由 {base} 降至 "
                                f"{len(covered)}，不得回退")
        elif len(covered) > base:
            rep.stat("覆盖率棘轮", f"{label} 较基线 {base} 提升至 {len(covered)}，"
                                  f"可提高 BASELINE['{key}']")
        elif not covered:
            rep.warn("覆盖率", f"{len(defined)} 条 {label} 无一被设计或测试卷显式"
                              f"引用；追踪制品建立前无法证明需求有设计与测试覆盖")
        else:
            rep.warn("覆盖率", f"仅 {len(covered)}/{len(defined)} 条 {label} 被设计或"
                              f"测试卷显式引用")


def check_density(vols: dict[str, str], rep: Report) -> None:
    """可评审性棘轮：超长表格单元格只减不增。"""
    long_cells = []
    for name, text in vols.items():
        for i, line in enumerate(text.split("\n"), 1):
            if line.startswith("|"):
                for cell in line.split("|"):
                    if len(cell) > LONG_CELL_CHARS:
                        long_cells.append((len(cell), name, i))
    long_cells.sort(reverse=True)
    rep.stat("超长单元格", f"{len(long_cells)} 个 (>{LONG_CELL_CHARS} 字符)")

    base = BASELINE["long_cells"]
    if len(long_cells) > base:
        worst = long_cells[0]
        rep.error("可评审性", f"超长表格单元格由 {base} 增至 {len(long_cells)}，"
                              f"最长 {worst[0]} 字符 @ {worst[1]}:{worst[2]}")
    elif long_cells:
        rep.warn("可评审性", f"{len(long_cells)} 个单元格超过 {LONG_CELL_CHARS} 字符，"
                            f"最长 {long_cells[0][0]} 字符 @ "
                            f"{long_cells[0][1]}:{long_cells[0][2]}；建议拆分为子表")


CHECKS = [
    ("标识归属与卷间独立性", check_identifier_ownership),
    ("旧引用清理", check_stale_references),
    ("卷内引用可解析", check_volume_local_refs),
    ("权限审批种子对齐", check_seed),
    ("章节编号树", check_numbering),
    ("格式与合卷痕迹", check_format),
    ("需求覆盖率", check_coverage),
    ("可评审性", check_density),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="文档基线机检")
    parser.add_argument("--quiet", action="store_true", help="只输出失败项与总结")
    args = parser.parse_args()

    vols = volumes()
    if not vols:
        print(f"未在 {DOCS} 找到文档卷", file=sys.stderr)
        return 1

    rep = Report()
    for label, fn in CHECKS:
        before = len(rep.items)
        fn(vols, rep)
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
