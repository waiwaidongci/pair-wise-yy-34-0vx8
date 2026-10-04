# 工伤事故调查与纠正措施

记录工伤经过、伤害、现场和证人，维护调查、纠正措施、验证与关闭流程。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8311
```

默认端口为`8311`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `GET /api/items/{id}/records`
- `GET /api/items/{id}/conflicts`
- `GET /api/items/{id}/snapshots`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`

允许角色：reporter, investigator, safety_manager, viewer。严重度越高、伤害指数越大或未关闭措施越多，优先级越高；严重事故必须在4小时内启动调查。

## 关闭复核（close review）

- **冻结**：事故关闭（`transition` 到 `closed`）时冻结事故版本与全部措施状态，生成一份有效快照（`close_snapshots`）。
- **失效**：关闭后若补录复诊/复发措施，关闭依据指纹（`basis_hash`）改变，当前结论立即失效：事故回到 `verification`，原快照保留为 `invalid`，列表与审计展示失效来源（`invalidation_source`）。
- **重新关闭**：再次关闭会冻结新快照，旧失效快照保留。
- **旧事故补齐**：启动时为已关闭但无快照的事故按现状补一份有效快照。

## 冲突稿（conflict draft）

两名调查员提交同一措施（`item_id` + `external_ref` 相同）时，先到者生效，后到者不再报 `409`，而是留一份冲突稿（`conflict_drafts`），可通过 `GET /api/items/{id}/conflicts` 查看。

## 操作号幂等（operation no）

写操作支持 `X-Operation-No`（或 `X-Operation-Id`）请求头，也可在请求体里带 `operation_no`。同一操作号只记账一次；审计写入失败后重试不会重复记账，直接回放已有结果。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
