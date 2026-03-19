package com.protect7.authanalyzer.uitesting.discovery;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.JsonObject;

/**
 * OpenAPI 解析出的端点 Schema，用于智能参数替换和 RequestBody 生成。
 */
public class EndpointSchema {

    /** 路径参数名 -> ParamSchema */
    private final Map<String, ParamSchema> pathParams;
    /** RequestBody 的 JSON Schema（OpenAPI schema 对象） */
    private final JsonObject requestBodySchema;
    /** OpenAPI components（用于 $ref 解析） */
    private final JsonObject components;

    public EndpointSchema(Map<String, ParamSchema> pathParams, JsonObject requestBodySchema) {
        this(pathParams, requestBodySchema, null);
    }

    public EndpointSchema(Map<String, ParamSchema> pathParams, JsonObject requestBodySchema, JsonObject components) {
        this.pathParams = pathParams != null ? new LinkedHashMap<>(pathParams) : Collections.emptyMap();
        this.requestBodySchema = requestBodySchema;
        this.components = components;
    }

    public Map<String, ParamSchema> getPathParams() {
        return Collections.unmodifiableMap(pathParams);
    }

    public JsonObject getRequestBodySchema() {
        return requestBodySchema;
    }

    public JsonObject getComponents() {
        return components;
    }

    /**
     * 单个参数的类型信息。
     */
    public static class ParamSchema {
        private final String type;
        private final String format;

        public ParamSchema(String type, String format) {
            this.type = type != null ? type.toLowerCase() : "string";
            this.format = format != null ? format.toLowerCase() : null;
        }

        public String getType() {
            return type;
        }

        public String getFormat() {
            return format;
        }
    }
}
