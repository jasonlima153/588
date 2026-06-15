# OctopusIMMultiPush

558 (OctopusIM) 多开分身推送隔离与重连引擎

## 功能

- **Keychain 物理隔离**: Hook SecItemAdd/CopyMatching/Update/Delete，使用 kSecAttrComment 标记实现分身间 Keychain 数据完全隔离
- **NSUserDefaults Token 缓存隔离**: 拦截 sppush.cacheDeviceTokenKey，添加实例后缀防止缓存覆盖
- **长连接重连守护**: 前后台切换时自动触发 AppService/IMAutoConnectSocket 重连机制
- **合规后台保活**: 仅使用 beginBackgroundTask，无音频/定位保活，过审安全

## 构建

### GitHub Actions (推荐)

推送代码到 main 分支即可自动触发 CI 构建。

### 本地构建 (Theos)

```bash
# 安装 Theos
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"

# 编译
cd OctopusIMMultiPush
make FINALPACKAGE=1

# 产物
# .theos/obj/debug/OctopusIMMultiPush.dylib
# .theos/packages/*.deb
```

### 本地构建 (Xcode clang)

```bash
SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
CLANG=$(xcrun --sdk iphoneos --find clang)

# 需要先预处理 Logos 语法 (.xm -> .m)
# 然后编译
$CLANG -arch arm64 -isysroot "$SDK_PATH" -target arm64-apple-ios15.0 \
  -dynamiclib -fobjc-arc \
  -framework Foundation -framework UIKit -framework Security \
  -install_name @executable_path/OctopusIMMultiPush.dylib \
  -o OctopusIMMultiPush.dylib Tweak.m
```

## 注入方式

将编译好的 `OctopusIMMultiPush.dylib` 注入到目标 IPA：

1. 解压 IPA
2. 将 dylib 放入 `Payload/xxx.app/`
3. 修改 Mach-O 加载命令（使用 insert_dylib 或 optool）
4. 重签名并打包

## 技术原理

详见 [558 推送分析报告](../558_OctopusIM_Push_Analysis_Report.docx)
