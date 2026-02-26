package com.protect7.authanalyzer.uitesting.discovery;

/**
 * 发现的隐藏 API 端点。
 */
public class DiscoveredEndpoint {

    public enum Source {
        JS("JS"),
        SWAGGER("Swagger");

        private final String displayName;

        Source(String displayName) {
            this.displayName = displayName;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }

    private final String method;
    private final String path;
    private final Source source;

    public DiscoveredEndpoint(String method, String path, Source source) {
        this.method = method != null ? method.toUpperCase() : "GET";
        this.path = path != null ? path : "";
        this.source = source != null ? source : Source.JS;
    }

    public String getMethod() {
        return method;
    }

    public String getPath() {
        return path;
    }

    public Source getSource() {
        return source;
    }

    @Override
    public String toString() {
        return method + " " + path + " (" + source + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DiscoveredEndpoint that = (DiscoveredEndpoint) o;
        return method.equals(that.method) && path.equals(that.path);
    }

    @Override
    public int hashCode() {
        return 31 * method.hashCode() + path.hashCode();
    }
}
