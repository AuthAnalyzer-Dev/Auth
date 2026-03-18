# Burp 插件加载 NoSuchFileException 排查指南

## 错误现象

```
java.nio.file.NoSuchFileException: C:\Users\...\AppData\Local\Temp\burp...tmp\-1
```

路径末尾的 `\-1` 表明 Burp 在解析/解压 JAR 时使用了无效索引，属于 Burp 内部处理逻辑问题。

---

## 可能原因

| 原因 | 说明 |
|------|------|
| **Java 23** | Burp 官方建议扩展使用 Java 21 及以下；用 Java 23 运行 Burp 可能导致兼容性问题 |
| **Burp 版本** | 新版本 Burp 对 JAR 加载逻辑有调整，可能引入 bug |
| **临时目录** | 杀毒软件或系统清理可能提前删除 Burp 的临时文件 |
| **Fat JAR 结构** | `jar-with-dependencies` 生成的包结构可能与部分 Burp 版本不兼容 |

---

## 排查步骤

### 1. 使用 Java 21 运行 Burp（优先尝试）

```bash
# 检查当前 Java 版本
java -version

# 若为 Java 23，安装并切换到 Java 21
# 启动 Burp 时指定 Java 21：
"C:\Program Files\Java\jdk-21\bin\java.exe" -jar burpsuite.jar
```

或在 Burp 启动配置中指定 Java 21 路径。

### 2. 修改 Burp 临时文件目录

- 打开 **Settings → Suite → Temporary file location**
- 将临时目录改为不含空格、中文的路径，例如：`C:\BurpTemp`
- 重启 Burp 后再次加载插件

### 3. 临时关闭杀毒/安全软件

- 将 Burp 和 `%TEMP%` 加入白名单
- 或临时关闭实时防护后重试加载

### 4. 清理后重新构建

```bash
mvn clean package
```

删除 `target/` 后重新打包，再加载新生成的 JAR。

---

## 若仍无法解决

可尝试改用 **maven-shade-plugin** 替代 maven-assembly，生成结构不同的 Fat JAR，有时能规避 Burp 的加载问题。详见项目 `pom.xml` 的 shade 配置说明。
