package com.protect7.authanalyzer.uitesting.runner;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;

public class ProxyDriverManager {

    private static WebDriver driver;

    /**
     * Start ChromeDriver. If useProxy==true, all traffic will go through proxyHost:proxyPort.
     * Returns the WebDriver instance.
     */
    public static synchronized WebDriver startDriver(boolean useProxy, String proxyHost, int proxyPort, boolean headless) {
        if (driver != null) {
            return driver;
        }

        WebDriverManager.chromedriver().setup();
        ChromeOptions options = new ChromeOptions();

        // Basic stability flags
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        options.addArguments("--disable-gpu");
        options.addArguments("--remote-allow-origins=*");
        options.setAcceptInsecureCerts(true); // accept insecure certs so Burp MITM won't break navigation
        options.addArguments("--ignore-certificate-errors"); // tolerate certs

        if (headless) {
            // modern headless flag
            options.addArguments("--headless=new");
        }

        if (useProxy) {
            String proxyArg = String.format("http://%s:%d", proxyHost, proxyPort);
            options.addArguments("--proxy-server=" + proxyArg);
        }

        // create driver
        driver = new ChromeDriver(options);
        return driver;
    }

    public static synchronized WebDriver getDriver() {
        return driver;
    }

    public static synchronized void stopDriver() {
        try {
            if (driver != null) {
                driver.quit();
            }
        } catch (Throwable ignored) {}
        driver = null;
    }
}
