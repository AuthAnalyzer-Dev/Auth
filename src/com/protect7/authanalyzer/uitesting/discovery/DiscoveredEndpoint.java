package com.protect7.authanalyzer.uitesting.discovery;

import java.util.Collections;
import java.util.List;

/**
 * 发现的隐藏 API 端点。
 */
public class DiscoveredEndpoint {

    public enum Source {
        JS("JS"),
        SWAGGER("Swagger"),
        SOURCE_MAP("SourceMap"),
        GRAPHQL("GraphQL");

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
    /** 仅 Swagger 来源时有值，用于智能参数替换和 Body 生成 */
    private final EndpointSchema endpointSchema;
    /** 仅 GraphQL 来源时可能有值，用于构造 query body */
    private final String graphqlOperation;
    /** 仅 GraphQL 来源时可能有值，用于构造带参数的 query */
    private final List<String> graphqlArgNames;
    /** 仅 GraphQL 来源时可能有值，与 graphqlArgNames 一一对应的类型（如 ID, String, Int） */
    private final List<String> graphqlArgTypes;
    /** 仅 GraphQL 来源时可能有值，"query" 或 "mutation" */
    private final String graphqlOperationType;

    public DiscoveredEndpoint(String method, String path, Source source) {
        this(method, path, source, null, null, null, null, null);
    }

    public DiscoveredEndpoint(String method, String path, Source source, EndpointSchema endpointSchema) {
        this(method, path, source, endpointSchema, null, null, null, null);
    }

    public DiscoveredEndpoint(String method, String path, Source source, EndpointSchema endpointSchema, String graphqlOperation) {
        this(method, path, source, endpointSchema, graphqlOperation, null, null, null);
    }

    public DiscoveredEndpoint(String method, String path, Source source, EndpointSchema endpointSchema,
            String graphqlOperation, List<String> graphqlArgNames) {
        this(method, path, source, endpointSchema, graphqlOperation, graphqlArgNames, null, null);
    }

    public DiscoveredEndpoint(String method, String path, Source source, EndpointSchema endpointSchema,
            String graphqlOperation, List<String> graphqlArgNames, String graphqlOperationType) {
        this(method, path, source, endpointSchema, graphqlOperation, graphqlArgNames, null, graphqlOperationType);
    }

    public DiscoveredEndpoint(String method, String path, Source source, EndpointSchema endpointSchema,
            String graphqlOperation, List<String> graphqlArgNames, List<String> graphqlArgTypes, String graphqlOperationType) {
        this.method = method != null ? method.toUpperCase() : "GET";
        this.path = path != null ? path : "";
        this.source = source != null ? source : Source.JS;
        this.endpointSchema = endpointSchema;
        this.graphqlOperation = graphqlOperation;
        this.graphqlArgNames = graphqlArgNames != null ? Collections.unmodifiableList(graphqlArgNames) : null;
        this.graphqlArgTypes = graphqlArgTypes != null ? Collections.unmodifiableList(graphqlArgTypes) : null;
        this.graphqlOperationType = graphqlOperationType;
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

    /** 仅 Swagger 来源时可能非 null */
    public EndpointSchema getEndpointSchema() {
        return endpointSchema;
    }

    /** 仅 GraphQL 来源时可能非 null */
    public String getGraphqlOperation() {
        return graphqlOperation;
    }

    /** 仅 GraphQL 来源时可能非 null，用于构造带参数的 query */
    public List<String> getGraphqlArgNames() {
        return graphqlArgNames;
    }

    /** 仅 GraphQL 来源时可能非 null，与 graphqlArgNames 一一对应的类型 */
    public List<String> getGraphqlArgTypes() {
        return graphqlArgTypes;
    }

    /** 仅 GraphQL 来源时可能非 null，"query" 或 "mutation" */
    public String getGraphqlOperationType() {
        return graphqlOperationType;
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
        if (!method.equals(that.method) || !path.equals(that.path)) return false;
        String g1 = graphqlOperation;
        String g2 = that.graphqlOperation;
        return (g1 == null ? g2 == null : g1.equals(g2));
    }

    @Override
    public int hashCode() {
        int h = 31 * method.hashCode() + path.hashCode();
        return graphqlOperation != null ? 31 * h + graphqlOperation.hashCode() : h;
    }
}
