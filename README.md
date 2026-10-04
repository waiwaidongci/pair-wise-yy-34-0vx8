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
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/items/{id}/closures`，查看关闭快照（含已失效快照的冻结内容）
- `GET /api/audit`

允许角色：reporter, investigator, safety_manager, viewer。严重度越高、伤害指数越大或未关闭措施越多，优先级越高；严重事故必须在4小时内启动调查。

## 关闭复核

- 关闭时在同一事务内冻结事故版本和全部措施状态，生成关闭快照（`closure_snapshots`）。
- 归档后补录复诊/复发措施仍被允许，但关闭依据一变当前结论即失效：事故自动回到`verification`并递增版本，原快照标记`invalidated`并保留，安全经理持旧版本放行会被版本冲突拒绝；重新关闭会生成新快照。
- 两名调查员同时提交同一措施（相同`external_ref`）时先到者生效，后到者保留冲突稿（`record_conflicts`），`GET /api/items/{id}/records`同时返回`records`与`conflicts`。
- 审计事件携带操作号`op_id`（如`transition:{item}:{version}`、`record:{id}`），写入失败后按操作号恢复，重试不重复记账。
- 启动时自动为没有快照的旧事故按现状补齐快照（`source=backfill`，幂等）。
- 列表与详情的`closure`字段及审计中的`closure_invalidated`事件展示失效来源（触发记录、操作人、时间）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
