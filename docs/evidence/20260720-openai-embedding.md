# OpenAI Embedding 证据基线

## 核验信息

- 核验日期：2026-07-20
- 官方接口：`https://developers.openai.com/api/reference/resources/embeddings/methods/create`
- 官方模型页：`https://developers.openai.com/api/docs/models/text-embedding-3-small`

## 已确认事实

1. Embedding 使用 `POST /v1/embeddings` 与 Bearer API Key，不支持流式输出。
2. 当前官方接口枚举 `text-embedding-3-small`、`text-embedding-3-large` 与旧版 `text-embedding-ada-002`；初始目录只发布两个第三代模型。
3. 每个输入最多 8192 Token，字符串或 Token 数组批次最多 2048 项，单次请求全部输入累计最多 300000 Token。
4. `dimensions` 只适用于 `text-embedding-3` 及更新模型且最小值为 1；当前直接核验资料没有同时给出每个模型的精确最大值，因此初始目录不发布可选维度。
5. 官方 `encoding_format` 为 `float` 或 `base64`；Base64 结果不自描述坐标精度与维度，因此初始目录仅发布 `float`。
6. 响应通过 `data[].index` 对应输入，且包含实际模型标识；Driver 验证完整索引并拒绝非空的模型身份漂移。

## 保守边界

- 不接受 Token ID 数组、`user` 字段、静默分块或静默截断；VCP 初始 Profile 仅公开有稳定身份的文本批次。
- Driver 保留官方合同的维度与 Base64 投影能力，只有未来逐模型 Profile 明确发布相关范围后调用面才可使用。
- Router 不保存向量、不归一化向量，也不比较不同模型的向量空间。
