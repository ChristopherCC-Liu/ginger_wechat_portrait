# Notices and provenance

This repository is a fork of
[`Jiang59991/ginger_wechat_portrait`](https://github.com/Jiang59991/ginger_wechat_portrait).
The upstream snapshot did not include an explicit root software license when this
version was prepared. Existing upstream files retain their original copyright and
terms; this notice does not grant additional rights over them.

The Personal Agent v2 implementation was informed by public interface and product
ideas from these projects without copying their private data or generated profiles:

- `notdog1998/yourself-skill` (MIT): separation of self memory and persona,
  evidence-aware corrections, and version rollback concepts.
- `huohuoer/wechat-cli` (Apache-2.0): public documentation of WeChat 4.x database
  shard names and read-only schema conventions. Ginger's implementation is
  independent and uses the system SQLCipher executable instead of vendoring that
  project's decryption code or binaries.

No database, message export, wxid, model credential, Keychain item, generated
profile, runtime state, or third-party binary is part of the source distribution.
