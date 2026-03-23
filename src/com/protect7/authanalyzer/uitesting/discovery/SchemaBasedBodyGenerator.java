package com.protect7.authanalyzer.uitesting.discovery;

import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

/**
 * 基于 OpenAPI Schema 生成路径参数替换值和 RequestBody JSON。
 */
public final class SchemaBasedBodyGenerator {

    private static final Random RAND = new Random();
    private static final Pattern PATH_PARAM = Pattern.compile("\\{([^}]+)\\}");

    private SchemaBasedBodyGenerator() {}

    /**
     * 根据 ParamSchema 生成合适的替换值。
     */
    public static String generateParamValue(EndpointSchema.ParamSchema schema) {
        if (schema == null) return "1";
        String type = schema.getType();
        String format = schema.getFormat();

        if ("uuid".equals(format) || "guid".equals(format)) {
            return UUID.randomUUID().toString();
        }
        if ("email".equals(format)) {
            return "test@example.com";
        }
        if ("integer".equals(type) || "int32".equals(format) || "int64".equals(format)) {
            return String.valueOf(RAND.nextInt(10000) + 1);
        }
        if ("number".equals(type) || "float".equals(type) || "double".equals(type)) {
            return String.valueOf(RAND.nextDouble() * 1000);
        }
        if ("boolean".equals(type)) {
            return "true";
        }
        return "1";
    }

    /**
     * 将 path 中的 {param} 按 schema 替换为类型匹配的值。
     */
    public static String replacePathParams(String path, Map<String, EndpointSchema.ParamSchema> pathParams) {
        if (path == null) return "";
        if (pathParams == null || pathParams.isEmpty()) {
            return path.replaceAll("\\{[^}]+\\}", "1");
        }
        StringBuffer sb = new StringBuffer();
        Matcher m = PATH_PARAM.matcher(path);
        while (m.find()) {
            String paramName = m.group(1);
            EndpointSchema.ParamSchema ps = pathParams.get(paramName);
            String replacement = ps != null ? generateParamValue(ps) : "1";
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * 基于 OpenAPI schema 生成包含必填字段的 JSON Body。
     * 优先添加 required 字段，再添加可选字段以生成更完整的示例。
     */
    public static String generateRequestBody(JsonObject schema) {
        return generateRequestBody(schema, null);
    }

    /**
     * 基于 OpenAPI schema 生成 JSON Body，支持 $ref 解析（需传入 components）。
     */
    public static String generateRequestBody(JsonObject schema, JsonObject components) {
        if (schema == null) return "{}";
        try {
            JsonObject body = new JsonObject();
            java.util.Set<String> visitedRefs = new java.util.HashSet<>();
            buildFromSchema(body, schema, "", components, 0, 8, visitedRefs);
            return body.toString();
        } catch (Exception e) {
            return "{}";
        }
    }

    private static void buildFromSchema(JsonObject target, JsonObject schema, String path,
            JsonObject components, int depth, int maxDepth, java.util.Set<String> visitedRefs) {
        if (schema == null || depth > maxDepth) return;

        JsonElement refEl = schema.get("$ref");
        if (refEl != null && refEl.isJsonPrimitive()) {
            String ref = refEl.getAsString();
            if (visitedRefs.contains(ref)) return;
            visitedRefs.add(ref);
            JsonObject resolved = resolveRef(ref, components);
            if (resolved != null) buildFromSchema(target, resolved, path, components, depth + 1, maxDepth, visitedRefs);
            visitedRefs.remove(ref);
            return;
        }

        JsonObject props = null;
        if (schema.has("properties") && schema.get("properties").isJsonObject()) {
            props = schema.getAsJsonObject("properties");
        }
        if (props == null) return;

        java.util.Set<String> required = new java.util.HashSet<>();
        if (schema.has("required") && schema.get("required").isJsonArray()) {
            for (JsonElement r : schema.getAsJsonArray("required")) {
                if (r != null && r.isJsonPrimitive()) {
                    String name = r.getAsString();
                    if (name != null) required.add(name);
                }
            }
        }

        for (String key : props.keySet()) {
            if (!required.isEmpty() && !required.contains(key)) continue;  // 无 required 时添加全部，有则仅添加必填
            if (key == null) continue;
            JsonElement valEl = props.get(key);
            if (valEl == null || !valEl.isJsonObject()) continue;
            JsonObject propSchema = valEl.getAsJsonObject();
            JsonElement propType = propSchema != null ? propSchema.get("type") : null;
            if (propType == null || !propType.isJsonPrimitive()) continue;

            String t = propType.getAsString();
            if ("string".equals(t)) {
                target.add(key, new JsonPrimitive(defaultString(propSchema)));
            } else if ("integer".equals(t) || "number".equals(t)) {
                target.add(key, new JsonPrimitive(1));
            } else if ("boolean".equals(t)) {
                target.add(key, new JsonPrimitive(true));
            } else if ("array".equals(t)) {
                target.add(key, new JsonArray());
            } else if ("object".equals(t)) {
                JsonObject nested = new JsonObject();
                buildFromSchema(nested, propSchema, path + "." + key, components, depth + 1, maxDepth, visitedRefs);
                target.add(key, nested);
            }
        }
    }

    private static JsonObject resolveRef(String ref, JsonObject components) {
        if (ref == null || components == null || !ref.startsWith("#/components/schemas/")) return null;
        String name = ref.substring("#/components/schemas/".length());
        if (name.isEmpty()) return null;
        JsonElement schemasEl = components.get("schemas");
        if (schemasEl == null || !schemasEl.isJsonObject()) return null;
        JsonElement el = schemasEl.getAsJsonObject().get(name);
        return (el != null && el.isJsonObject()) ? el.getAsJsonObject() : null;
    }

    private static String defaultString(JsonObject schema) {
        JsonElement format = schema.get("format");
        if (format != null) {
            String f = format.getAsString();
            if ("email".equals(f)) return "test@example.com";
            if ("uuid".equals(f) || "guid".equals(f)) return UUID.randomUUID().toString();
            if ("date-time".equals(f)) return "2024-01-01T00:00:00Z";
        }
        return "test";
    }
}
