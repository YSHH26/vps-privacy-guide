# 不使用面板

你也可以不装 S-UI，直接单独跑 sing-box。这种方式用的是 [server.json](../examples/server.json)，靠手动改配置和 systemd 来管理。服务器还是需要 SSH、可信证书、三组节点凭据和防火墙设置。

## 与面板模式二选一

已经装了 S-UI 的话，先备份，再决定要不要迁过来。别直接覆盖它的数据库，也别另起一个 sing-box 去抢它的端口。S-UI 里的用户、TLS 和节点设置不是一份完整的 sing-box JSON，要导出来或者重新整理。

## 配置准备

1. 照 [官方安装说明](https://sing-box.sagernet.org/installation/package-manager/) 装好 [versions.json](../versions.json) 里对应版本的 sing-box。
2. 把 `examples/server.json` 复制成 `private/server.json`（这个目录不会进 Git），权限设成 600。
3. 给 AnyTLS 生成一个单独的随机密码；给 VLESS TLS 和 Reality 生成同一个用户 UUID，再生成 Reality 的密钥对和 short ID。
4. 把所有 `__占位符__` 都换掉。证书路径填 sing-box 进程能读到的真实路径，Reality 的目标照 [TLS 文档](tls.md) 来选。
5. 对应着填好 `private/client.json`。客户端里只放公钥，别放服务端私钥。

```sh
umask 077
mkdir -p private
cp examples/server.json private/server.json
cp examples/client.json private/client.json
chmod 600 private/server.json private/client.json
```

上面的 `cp` 只在第一次创建时用，已经有私有配置了就别再覆盖。凭据用本地编辑器填，别让它出现在共享终端的记录或聊天里。

## 校验和运行

```sh
sing-box check -c private/server.json
```

检查通过后，把配置装到服务实际读取的位置。先用 `systemctl cat sing-box` 看一下你这个发行版的 `ExecStart` 和配置路径，再安装；一般是 `/etc/sing-box/config.json`。

```sh
sudo install -d -m 700 /etc/sing-box
sudo install -m 600 private/server.json /etc/sing-box/config.json
sudo systemctl enable --now sing-box
sudo systemctl status sing-box --no-pager
```

上面假设服务读的就是这个路径，而且是第一次安装。已经在跑的服务要先备份，改完执行 `systemctl restart sing-box`；`enable --now` 不会让已经在跑的进程重新加载配置。证书文件要让服务实际的运行用户能读到，别图省事把私钥设成所有人可读。

## 和面板模式在维护上的区别

没有网页后台，没有流量用完自动停用，也没有订阅生成服务。加用户要改配置；证书续期以后要让 sing-box 重新加载新文件。配置、密钥和证书都要备份到仓库以外的地方，三个协议也要像面板模式一样，从头到尾实际连一遍。
