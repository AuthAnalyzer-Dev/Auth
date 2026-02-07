# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AuthAnalyzer is a Burp Suite extension for automated authorization bypass testing. It intercepts HTTP traffic, replays requests with different authentication contexts (sessions), and compares responses to detect access control vulnerabilities.

## Build Commands

```bash
# Build the extension JAR
mvn clean package

# The output JAR will be at:
# target/AuthAnalyzer-1.1.14-jar-with-dependencies.jar

# Compile only
mvn compile

# Clean build artifacts
mvn clean
```

## Architecture

### Core Request Processing Flow

```
HTTP Traffic → HttpListener → Filter Chain → RequestController → Session Analysis
```

1. **HttpListener** intercepts all Burp traffic
2. **Filter Chain** determines which requests to analyze (scope, file types, methods, etc.)
3. **RequestController** processes each request:
   - For each configured Session, modifies the request with session-specific tokens/headers
   - Sends modified request to server
   - Extracts dynamic tokens from responses (CSRF, session tokens)
   - Compares responses to detect bypass (SAME/SIMILAR/DIFFERENT)
4. Results stored in session maps and displayed in GUI table

### Session System

**Session** (`entities/Session.java`) represents a user/privilege level with:
- Headers to replace/remove
- Tokens (dynamic/static parameters to inject)
- Match & Replace rules
- Request/Response map storing analysis results

**CurrentConfig** (`util/CurrentConfig.java`) is the singleton managing:
- List of all sessions
- Thread pool for parallel request processing
- Filter chain configuration
- Global table model

### Token Extraction & Replacement

**Token** (`entities/Token.java`) represents parameters that need extraction/replacement:
- Types: Static value, Auto-extract (HTML/JSON/cookies), From/To string extraction, Prompt
- Locations: URL, Cookie, Body, JSON, Path, Header

**ExtractionHelper** (`util/ExtractionHelper.java`):
- Extracts tokens from responses using Jsoup (HTML), JSON parsing, cookie parsing, string patterns

**RequestModifHelper** (`util/RequestModifHelper.java`):
- Modifies requests with session-specific values
- Handles header replacement, parameter injection, JSON manipulation

### Bypass Detection Logic

Located in `RequestController.java`:
- **SAME**: Response body identical AND status code matches → Potential bypass
- **SIMILAR**: Status code matches AND response length within ±5% → Potential bypass
- **DIFFERENT**: Responses differ significantly → No bypass

### GUI Structure

```
BurpExtender (main tab)
├── Analyzer Tab
│   ├── ConfigurationPanel (top)
│   │   ├── Start/Stop/Pause controls
│   │   ├── SessionTabbedPane (session tabs)
│   │   │   └── SessionPanel (per session)
│   │   │       ├── Headers configuration
│   │   │       ├── TokenPanel (token list)
│   │   │       └── StatusPanel (session state)
│   │   └── Filter checkboxes
│   └── CenterPanel (bottom)
│       ├── Request table (RequestTableModel)
│       └── RequestResponsePanel (side-by-side comparison)
└── UI Testing Tab (in development)
    ├── ControlsPanel (configuration)
    ├── Request table (shared with Analyzer)
    └── Detail panel
```

### UITesting Feature (In Development)

Selenium-based automated testing with click mirroring between browsers:

**ProxyDriverManager** (`uitesting/runner/ProxyDriverManager.java`):
- Manages two Chrome WebDriver instances (Driver A and Driver B)
- Configures proxy to route through Burp (127.0.0.1:8080)
- Supports headless mode

**Replayer** (`uitesting/runner/Replayer.java`):
- Captures clicks in browser A and replays them in browser B
- Injects JavaScript event listeners to capture click events with CSS selectors
- Automatically injects cookies (tiup_uid, session) for browser B
- Two modes: continuous mirroring (background thread) or one-time mirror

**Integration**: UITesting panel binds to main AuthAnalyzer's RequestTableModel to display captured requests in real-time.

## Key Files

- `src/burp/BurpExtender.java` - Main extension entry point, implements IBurpExtender
- `controller/HttpListener.java` - Intercepts HTTP traffic from Burp
- `controller/RequestController.java` - Core authorization testing logic
- `util/CurrentConfig.java` - Singleton managing global state
- `entities/Session.java` - Session entity with tokens and configuration
- `util/RequestModifHelper.java` - Request modification with session tokens
- `util/ExtractionHelper.java` - Token extraction from responses
- `gui/main/ConfigurationPanel.java` - Session configuration UI
- `gui/main/CenterPanel.java` - Request table and comparison view
- `uitesting/runner/Replayer.java` - Selenium click mirroring (new feature)

## Dependencies

- **Burp Extender API 2.3** - Burp Suite integration
- **Gson 2.8.6** - JSON serialization for config persistence
- **Jsoup 1.13.1** - HTML parsing for token extraction
- **Selenium 4.35.0** - Browser automation for UITesting
- **WebDriverManager 6.3.2** - Automatic browser driver management
- **JUnit 4.11** - Testing framework

## Development Notes

### Filter System

Filters in `filter/` package determine which requests to analyze:
- InScopeFilter, OnlyProxyFilter, FileTypeFilter, MethodFilter, StatusCodeFilter, PathFilter, QueryFilter
- Each filter implements `RequestFilter` interface with `filterRequest()` method

### Thread Safety

- RequestController uses thread pool executor for parallel request processing
- Session.requestResponseMap is ConcurrentHashMap for thread-safe access
- Table model updates trigger Swing EDT events

### Configuration Persistence

- Sessions saved/loaded as JSON via Gson
- Configuration stored in Burp extension state
- DataStorageProvider handles serialization

### Working with Sessions

When modifying session logic:
1. Update Session entity if adding new fields
2. Update SessionPanel GUI for user input
3. Update ConfigurationPanel for session creation/validation
4. Update RequestModifHelper if changing request modification logic
5. Update ExtractionHelper if changing token extraction logic

### Working with UITesting

The UITesting feature is under active development:
- ProxyDriverManager handles WebDriver lifecycle
- Replayer uses JavaScript injection for event capture
- Cookie injection happens automatically before replay
- Requests captured via Burp proxy are displayed in shared table model