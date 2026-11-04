# Architecture (draft)

Layers: `domain` (models/rules), `policy` (YAML load/validate/evaluate), `store` (SQLite only),
`audit` (JSONL + hash chain), `service` (use cases, no printing), `cli` (thin front-end).
Time comes from an injectable clock so tests never wait. All timestamps are UTC (ISO 8601).