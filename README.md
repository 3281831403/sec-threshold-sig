门限签名上线后，两个伪造的部分签名拼在一起就能通过聚合校验：份额摘要不绑定消息，同一份额可跨消息复用；份额摘要不绑定索引，份额可被顶替；去重按键值而不是索引，不同索引被判重复；阈值判定用原始列表长度，重复份额刷数量；聚合不校验单个份额，伪造份额直接参与；聚合结果不含参与索引集合，无法审计；聚合校验不比对消息，签名可跨消息复用；索引越界不拒绝，越界份额参与插值；策略校验不检查阈值是否小于二；批量聚合复用份额集合，第二个请求沿用第一个请求的份额。thsig/aggregate.py 是核心，tests/test_aggregate.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 元信息

| 方向 | 类别 | 模式 | 技术栈 | 外部依赖 |
|---|---|---|---|---|
| 安全 | 漏洞检测与攻防 | Bugfix | Python 3, pytest | 无外部依赖 |

## 运行方式

在仓库根目录执行：

```text
python -m pytest tests -q
```

初始桩状态下预期输出恰好为 `15 failed`，并且 15 个失败必须全部是 `NotImplementedError`；实现完成后应为 `15 passed`。测试目录通过 `tests/conftest.py` 把 `src` 加入 `sys.path`，不需要安装包，也不需要联网。

## 约束

- `tests/` 是验收基准，不可修改、跳过、删除或重命名；不得改动断言、fixture 或测试数据。
- 只实现 `src/thsig/aggregate.py` 中的 8 个公开函数，保持函数名和签名不变。
- 只使用 Python 标准库，不引入外部依赖。
- 聚合必须做真实插值，不能用“任意若干份额相加”或单个份额冒充阈值签名。

## src 布局

```text
sec-threshold-sig/
  README.md
  pyproject.toml
  tests/
    conftest.py
    test_aggregate.py
  src/
    thsig/
      __init__.py
      aggregate.py       # 唯一实现文件，恰好 8 个桩
```

## 密码学契约

### 群参数

固定使用下面的 256 位安全素数群，测试数据全部基于它：

```text
P = 105691714255508482121613639744579206110468084374417573448624699383685088663807
Q = 52845857127754241060806819872289603055234042187208786724312349691842544331903
G = 4
```

其中 `P = 2*Q + 1`，`P` 与 `Q` 均为素数，`G` 在模 `P` 下的阶为 `Q`。参与者总数 `n = 5`，阈值 `threshold = 3`。

### 消息标量

消息到标量的映射是协议的一部分，必须逐字实现：

```python
raw = message.encode("utf-8")
material = b"thsig/msg/v1" + len(raw).to_bytes(4, "big") + raw
h = int.from_bytes(hashlib.sha256(material).digest(), "big") % Q
```

### 份额与公开承诺

测试使用二次多项式 `f(x) = A0 + A1*x + A2*x**2 mod Q` 做 Shamir 分享：

- 第 `i` 个私密份额为 `s_i = f(i) mod Q`，`i` 取 1 到 5。
- 公开承诺为 `C_i = pow(G, s_i, P)`。
- 群公钥为 `Y = pow(G, A0, P)`，可由任意 3 个承诺插值得到。
- 对消息的部分签名为 `sigma_i = s_i * h mod Q`，其中 `h` 是上面的消息标量。

`public` 与 `public_set` 使用同一种结构：

```python
{
    "n": 5,
    "p": P,
    "q": Q,
    "g": G,
    "commitments": {1: C1, 2: C2, 3: C3, 4: C4, 5: C5},
}
```

### 份额包

每个 partial 是下面的字典，`public` 是该份额对应的完整公开参数：

```python
{
    "index": 3,
    "share": sigma_3,
    "public": public,
}
```

`index` 必须是 `int` 且位于闭区间 `[1, n]`；`share` 必须是 `int` 且位于 `[0, q)`。`bool` 是 `int` 的子类，但这里必须拒绝 `True` / `False` 作为索引或份额。

### 8 个函数的硬性行为

1. `share_digest(message, index, share) -> str`
   - 返回 64 位小写十六进制字符串，同样输入必须稳定。
   - 必须同时绑定消息、索引和份额；消息与索引的拼接不能产生边界歧义（例如 `("ab", 12)` 与 `("ab1", 2)` 必须不同）。
   - 只用长度前缀或等价的无歧义编码，禁止只对 `message + str(index)` 之类直接哈希。

2. `verify_share(message, index, share, public) -> bool`
   - 索引必须严格是 `int`、在 `[1, n]` 内，且 `commitments` 中存在该索引；否则返回 `False`。
   - 份额必须严格是 `int`、在 `[0, q)` 内；否则返回 `False`。
   - 计算 `h = H(message)`，仅当 `pow(g, share, p) == pow(C_index, h, p)` 时返回 `True`。
   - 该检查天然拒绝消息不符的份额和被顶替到其他索引的份额。

3. `dedup_partials(partials) -> list`
   - 以 `index` 为唯一身份去重，不比较 `share` 或 `public` 的值。
   - 同一索引保留第一次出现的那一条，保持其余条目的原始相对顺序。
   - 不同索引即使 `share` 完全相同也必须全部保留。

4. `threshold_met(partials, threshold) -> bool`
   - 先去重，再按不同索引的数量判定，不能使用原始列表长度。
   - 当 `threshold < 2` 时返回 `False`；否则仅当不同索引数 `>= threshold` 时返回 `True`。

5. `aggregate(message, partials, threshold) -> dict`
   - `threshold` 必须是 `int` 且 `>= 2`，否则抛出 `ValueError`。
   - 聚合前逐个检查：索引越界、字段类型错误、同一索引出现不同份额（equivocation）、任一 `verify_share` 为 `False`，都必须抛出 `ValueError`。
   - 去重后不同索引数不足 `threshold` 时抛出 `ValueError`。
   - 对通过检查的份额计算拉格朗日系数并在 0 点插值：
     `lambda_i = product(j / (j - i)) mod Q`，`signature = sum(lambda_i * share_i) mod Q`。
   - 返回值必须恰好是 `{"signature": int, "indices": sorted_indices}` 两个键；`indices` 为升序去重列表，用于审计。不得附加其他键。

6. `verify_aggregate(message, signature, public_set) -> bool`
   - `signature` 是第 5 步返回的字典；索引必须非空、无重复、全部在 `[1, n]` 内且都有承诺。
   - 用签名中报告的索引和公开承诺插值出 `Y`，计算 `h = H(message)`，仅当 `pow(g, signature_value, p) == pow(Y, h, p)` 时返回 `True`。
   - 消息必须参与校验：为消息 A 生成的签名对消息 B 必须返回 `False`。
   - 对畸形输入返回 `False`，不要抛出异常。

7. `validate_policy(policy) -> list[str]`
   - 只做三项检查，返回稳定顺序的问题码列表；无问题时返回空列表。
   - `threshold` 不是 `int` 或小于 2：追加 `"threshold_below_two"`。
   - `verify_shares` 不为 `True`：追加 `"shares_not_verified"`。
   - `bind_message` 不为 `True`：追加 `"message_not_bound"`。
   - 缺失字段按不通过处理，顺序固定为上述三项。

8. `aggregate_batch(requests, policy) -> dict`
   - 先调用 `validate_policy`；有问题时抛出 `ValueError`。
   - `requests` 是请求列表，每个请求为 `{"message": str, "partials": list}`。
   - 每个请求独立调用 `aggregate(request["message"], request["partials"], policy["threshold"])`。
   - 返回 `{"results": [...]}`，结果顺序与请求顺序一致；每个元素必须与单独调用 `aggregate` 完全相等。
   - 禁止跨请求复用份额集合、缓存或累加器；第二个请求只能看到自己的 partials。

## 10 个缺陷

1. 份额摘要不绑定消息，同一份额可跨消息复用。
2. 份额摘要不绑定索引，份额可被顶替。
3. 去重按键值而不是索引，不同索引被判重复。
4. 阈值判定用原始列表长度，重复份额刷数量。
5. 聚合不校验单个份额，伪造份额直接参与。
6. 聚合结果不含参与索引集合，无法审计。
7. 聚合校验不比对消息，签名可跨消息复用。
8. 索引越界不拒绝，越界份额参与插值。
9. 策略校验不检查阈值是否小于二。
10. 批量聚合复用份额集合，第二个请求沿用第一个请求的份额。

## 15 个测试与覆盖点

| 测试 | 覆盖点 |
|---|---|
| test_defect_01_share_digest_binds_message | 缺陷 1，消息绑定与跨消息拒绝 |
| test_defect_02_share_digest_binds_index | 缺陷 2，索引绑定与份额顶替拒绝 |
| test_defect_03_dedup_by_index_not_share_value | 缺陷 3，按索引去重 |
| test_defect_04_threshold_counts_unique_indices_only | 缺陷 4，去重后计数 |
| test_defect_05_aggregate_verifies_each_share | 缺陷 5，伪造份额与冲突重复拒绝 |
| test_defect_06_aggregate_reports_participating_indices | 缺陷 6，参与索引审计 |
| test_defect_07_verify_aggregate_binds_message | 缺陷 7，聚合签名消息绑定 |
| test_defect_08_out_of_range_index_rejected | 缺陷 8，越界索引拒绝 |
| test_defect_09_policy_flags_threshold_below_two | 缺陷 9，策略阈值检查 |
| test_defect_10_batch_requests_do_not_share_partials | 缺陷 10，批请求隔离 |
| test_threshold_met_aggregate_succeeds_and_verifies | 达到阈值成功且可验证 |
| test_below_threshold_aggregation_fails | 少于阈值即失败 |
| test_duplicate_partials_counted_once | 重复份额只算一次 |
| test_message_mismatched_partial_rejected | 消息不符的份额被拒 |
| test_batch_results_match_individual_aggregation | 批量结果等于单独聚合 |

## 初始失败特征

```text
$ python -m pytest tests -q
15 failed
```

15 个失败都必须在第一次调用对应桩函数时以 `NotImplementedError` 结束；不允许出现收集错误、fixture 错误、导入错误或断言失败。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

