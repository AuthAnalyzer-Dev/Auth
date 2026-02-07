package com.protect7.authanalyzer.uitesting.runner;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;

public class ProxyDriverManager {

    private static WebDriver driver;       // A 账号（主浏览器）
    private static WebDriver mirrorDriver; // B 账号（镜像浏览器）

    /**
     * Start ChromeDriver for PRIMARY (A). If useProxy==true, all traffic will go through proxyHost:proxyPort.
     */
    public static synchronized WebDriver startDriver(boolean useProxy, String proxyHost, int proxyPort, boolean headless) {
        if (driver != null) return driver;
        driver = createChrome(useProxy, proxyHost, proxyPort, headless, "BrowserA");
        return driver;
    }

    /** New: start ChromeDriver for MIRROR (B). */
    public static synchronized WebDriver startMirrorDriver(boolean useProxy, String proxyHost, int proxyPort, boolean headless) {
        if (mirrorDriver != null) return mirrorDriver;
        mirrorDriver = createChrome(useProxy, proxyHost, proxyPort, headless, "BrowserB");
        return mirrorDriver;
    }

    private static ChromeDriver createChrome(boolean useProxy, String proxyHost, int proxyPort, boolean headless, String browserTag) {
        WebDriverManager.chromedriver().setup();
        ChromeOptions options = new ChromeOptions();

        // Basic stability flags
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        options.addArguments("--disable-gpu");
        options.addArguments("--remote-allow-origins=*");
        options.setAcceptInsecureCerts(true);
        options.addArguments("--ignore-certificate-errors");

        if (headless) {
            options.addArguments("--headless=new");
        }
        if (useProxy) {
            String proxyArg = String.format("http://%s:%d", proxyHost, proxyPort);
            options.addArguments("--proxy-server=" + proxyArg);
        }
        // Add custom user-agent to distinguish browsers
        if (browserTag != null && !browserTag.isEmpty()) {
            options.addArguments("--user-agent=Mozilla/5.0 (AuthAnalyzer-" + browserTag + ")");
        }
        return new ChromeDriver(options);
    }

    public static synchronized WebDriver getDriver() {
        return driver;
    }

    /** New */
    public static synchronized WebDriver getMirrorDriver() {
        return mirrorDriver;
    }

    public static synchronized void stopDriver() {
        try { if (driver != null) driver.quit(); } catch (Throwable ignored) {}
        driver = null;
    }

    /** New */
    public static synchronized void stopMirrorDriver() {
        try { if (mirrorDriver != null) mirrorDriver.quit(); } catch (Throwable ignored) {}
        mirrorDriver = null;
    }

    /** New */
    public static synchronized void stopAll() {
        stopDriver();
        stopMirrorDriver();
    }
}
