## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Prefer the graphify MCP tools over the CLI when they are available: `get_node` / `get_neighbors` for a known symbol, `shortest_path` for how two things connect, `query_graph` for open questions. Same data, no shell overhead.
- Start narrow and small: look up a known symbol or file before asking an open question, and pass `token_budget: 800` (CLI: `--budget 800`). Raise it only when the result says it was truncated and the answer wasn't in what came back. For open questions, add `context_filter: ["call"]` (CLI: `--context call`) or `--seed <file>` to stop config and type nodes crowding out the call path.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `PYTHONHASHSEED=0 graphify update .` to keep the graph current (AST-only, no API cost). Git hooks also do this after every commit. The fixed seed keeps community IDs stable, so the hand-written names in graphify-out/.graphify_labels.json stay attached to the right groups. After editing that file, apply the names with `PYTHONHASHSEED=0 graphify cluster-only . --no-label`: `update` skips writing when the graph itself hasn't changed. Rebuild with `update`, not `extract`: the two index different files and produce different groups.
- The Obsidian vault at graphify-out/obsidian/ is for humans browsing the graph; don't read it for codebase questions (use query/path/explain). Refresh it with `graphify export obsidian --dir graphify-out/obsidian`.
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
