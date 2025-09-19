package com.protect7.authanalyzer.uitesting.runner;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.io.PrintWriter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UITestRunner {

    public static void run(String baseUrl, String targetUrl, String tiupUid, String session,
                           PrintWriter stdout, PrintWriter stderr) {

        WebDriver driver = null;
        try {
            // 自动下载并准备 chromedriver 二进制
            WebDriverManager.chromedriver().setup();

            ChromeOptions options = new ChromeOptions();
            options.addArguments("--no-sandbox");
            options.addArguments("--disable-dev-shm-usage");
            options.addArguments("--disable-gpu");
            options.addArguments("--remote-allow-origins=*");
            // 如果你要在无界面环境运行（例如 CI / headless），启用 headless
            // options.addArguments("--headless=new");
            driver = new ChromeDriver(options);

            stdout.println("Chrome 浏览器已启动");

            // 打开 baseUrl 使得能设置 domain 级别的 cookie
            driver.get(baseUrl);
            stdout.println("已访问 Base URL: " + baseUrl);

            Cookie tiupUidCookie = new Cookie.Builder("tiup_uid", tiupUid)
                    .domain(getDomain(baseUrl))
                    .path("/")
                    .build();
            Cookie sessionCookie = new Cookie.Builder("session", session)
                    .domain(getDomain(baseUrl))
                    .path("/")
                    .build();

            driver.manage().addCookie(tiupUidCookie);
            driver.manage().addCookie(sessionCookie);
            stdout.println("Cookies 设置完成");

            // 刷新页面以应用 cookie
            driver.get(baseUrl);
            stdout.println("已刷新页面，应用 Cookies");

            // 加载目标 URL
            driver.get(targetUrl);
            stdout.println("已访问目标 URL: " + targetUrl);
            Thread.sleep(2000);

            List<WebElement> links = driver.findElements(By.xpath("//a[@href='javascript:void(0)']"));
            List<String> linksText = new ArrayList<>();

            for (WebElement link : links) {
                String text = link.getText();
                if (text != null && !text.trim().isEmpty()) {
                    linksText.add(text.trim());
                }
            }
            stdout.println("找到 " + linksText.size() + " 个链接");

            Set<String> visited = new HashSet<>();

            for (String linkText : linksText) {
                if (visited.contains(linkText)) {
                    continue;
                }

                WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(20));
                WebElement link = wait.until(ExpectedConditions.elementToBeClickable(
                        By.xpath("//a[@href='javascript:void(0)' and contains(normalize-space(.), \"" + escapeXpath(linkText) + "\")]")));

                visited.add(linkText);
                stdout.println("点击链接: " + linkText);

                link.click();
                Thread.sleep(2000);

                driver.get(targetUrl);
                stdout.println("返回到目标页面");
                Thread.sleep(1000);
            }

            stdout.println("任务完成，关闭浏览器。");

        } catch (Exception e) {
            stderr.println("发生错误: " + e.getMessage());
            e.printStackTrace(stderr);
        } finally {
            try {
                if (driver != null) {
                    driver.quit();
                }
            } catch (Exception ex) {
                stderr.println("关闭浏览器时出错: " + ex.getMessage());
            }
        }
    }

    private static String getDomain(String url) {
        if (url == null) return null;
        String tmp = url.toLowerCase().replaceAll("https?://", "");
        String host = tmp.split("/")[0];
        return host;
    }

    // 简单转义引号以安全插入 xpath contains()
    private static String escapeXpath(String s) {
        if (s == null) return "";
        return s.replace("\"", "\\\"").replace("'", "\\'");
    }
}
