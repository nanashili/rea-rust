import com.atxx.jhmcp.*;
import com.google.gson.*;
import io.modelcontextprotocol.kotlin.sdk.server.*;
import io.modelcontextprotocol.kotlin.sdk.types.*;
import jadx.api.*;
import jadx.api.plugins.input.data.ICodeReader;
import jadx.api.plugins.input.data.IMethodRef;
import jadx.api.plugins.input.insns.InsnIndexType;
import jadx.api.plugins.input.insns.Opcode;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.nodes.*;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;
import kotlin.Unit;
import kotlin.ResultKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlinx.coroutines.BuildersKt;
import kotlinx.io.CoreKt;
import kotlinx.io.JvmCoreKt;

/** REA-owned metadata boundary for the unmodified jadx-headless-mcp 0.7.1 JAR. */
class ReaJadxBridge {
  private static final Gson JSON = new Gson();
  private final SessionHolder holder;
  private JadxSession indexedSession;
  private Map<String, List<ClassSnapshot>> classes = Map.of();

  private record MethodSnapshot(String name, String rawName, String shortId, List<String> bodyAbsenceMarkers,
      Map<String, Object> summary) {}
  private record ClassSnapshot(JavaClass node, List<MethodSnapshot> methods, Map<String, Object> summary) {}

  private static final class InputFailure extends IllegalArgumentException {
    final String field;
    InputFailure(String field, String message) { super(message); this.field = field; }
  }

  private ReaJadxBridge(SessionHolder holder) { this.holder = holder; }

  private static CallToolResult text(String value, boolean failed) {
    return new CallToolResult(List.of(new TextContent(value, null, null)), failed, null, null);
  }

  private static CallToolResult json(Object value) { return text(JSON.toJson(value), false); }

  /** Translate the typed load outcome before upstream drops its exception identity. */
  static Object loadResult(Object result) {
    try { ResultKt.throwOnFailure(result); }
    catch (Throwable failure) {
      if (failure instanceof java.util.concurrent.CancellationException
          || failure instanceof Error && !(failure instanceof OutOfMemoryError)) return result;
      if (failure instanceof OutOfMemoryError) {
        String reason = failure.getMessage();
        boolean heap = "Java heap space".equals(reason) || "GC overhead limit exceeded".equals(reason);
        Map<String, Object> reply = new LinkedHashMap<>();
        reply.put("kind", "jvm-memory-failure");
        reply.put("memory_area", heap ? "heap" : "unknown");
        reply.put("exception_type", "java.lang.OutOfMemoryError");
        if (reason != null) reply.put("message", reason);
        reply.put("max_heap_bytes", Runtime.getRuntime().maxMemory());
        return text(JSON.toJson(reply), true);
      }
      return text("load failed: " + failure.getMessage(), true);
    }
    SessionHolder.LoadResult loaded = (SessionHolder.LoadResult) result;
    Map<String, Object> reply = new LinkedHashMap<>();
    reply.put("state", "LOADED");
    reply.put("apk_path", loaded.getApkPath());
    reply.put("class_count", loaded.getClassCount());
    reply.put("raw_class_count", loaded.getRawClassCount());
    reply.put("resource_count", loaded.getResourceCount());
    reply.put("load_duration_ms", loaded.getLoadDurationMs());
    reply.put("decompile_timeout_ms", loaded.getDecompileTimeoutMs());
    reply.put("threads", loaded.getThreads());
    reply.put("code_cache_size", loaded.getCodeCacheSize());
    reply.put("resources", loaded.getResourceMode());
    if (!loaded.getIncludePackages().isEmpty()) reply.put("include_packages", loaded.getIncludePackages());
    if (!loaded.getExcludePackages().isEmpty()) reply.put("exclude_packages", loaded.getExcludePackages());
    return json(reply);
  }

  private Object load(kotlinx.serialization.json.JsonObject arguments, SessionConfig defaults,
      Continuation<? super CallToolResult> continuation) {
    JsonObject args = JsonParser.parseString(arguments.toString()).getAsJsonObject();
    String path = string(args, "path");
    SessionConfig options = defaults.withLoadOverrides(
        optionalString(args, "include_packages"), optionalString(args, "exclude_packages"),
        args.has("threads") ? integer(args, "threads", 1) : null,
        args.has("code_cache_size") ? integer(args, "code_cache_size", 64) : null,
        optionalString(args, "resources"));
    return loadCall(next -> holder.load(path, options, next), continuation);
  }

  static Object loadCall(kotlin.jvm.functions.Function1<Continuation<SessionHolder.LoadResult>, Object> load,
      Continuation<? super CallToolResult> continuation) {
    var forwarded = new java.util.concurrent.atomic.AtomicBoolean();
    Continuation<SessionHolder.LoadResult> resumed = new Continuation<>() {
      public CoroutineContext getContext() { return continuation.getContext(); }
      public void resumeWith(Object result) {
        if (!forwarded.compareAndSet(false, true)) throw new IllegalStateException("Load resumed twice");
        Object translated;
        try { translated = loadResult(result); }
        catch (Throwable failure) { translated = ResultKt.createFailure(failure); }
        // Keep the consumer outside the translation catch, including inline completion.
        continuation.resumeWith(translated);
      }
    };
    Object result;
    try { result = load.invoke(resumed); }
    catch (Throwable failure) {
      if (forwarded.get()) ResultKt.throwOnFailure(ResultKt.createFailure(failure));
      result = ResultKt.createFailure(failure);
    }
    if (result == IntrinsicsKt.getCOROUTINE_SUSPENDED()) return result;
    Object translated = loadResult(result);
    ResultKt.throwOnFailure(translated);
    return translated;
  }

  private static String optionalString(JsonObject args, String name) {
    return args.has(name) ? string(args, name) : null;
  }

  private static String string(JsonObject args, String name) {
    JsonElement value = args.get(name);
    if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
      throw new IllegalArgumentException(name + " must be a string");
    return value.getAsString();
  }

  private static int integer(JsonObject args, String name, int fallback) {
    JsonElement value = args.get(name);
    if (value == null) return fallback;
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber())
      throw new IllegalArgumentException(name + " must be a nonnegative integer");
    try {
      int result = value.getAsBigDecimal().intValueExact();
      if (result < 0) throw new ArithmeticException();
      return result;
    } catch (ArithmeticException error) {
      throw new IllegalArgumentException(name + " must be a nonnegative integer", error);
    }
  }

  private JadxSession session() {
    JadxSession current = holder.current();
    if (current == null) throw new IllegalArgumentException("No APK loaded");
    return current;
  }

  private ClassSnapshot selected(JsonObject args) {
    JadxSession current = session();
    if (indexedSession != current) {
      Map<String, List<ClassSnapshot>> index = new LinkedHashMap<>();
      if (!current.getClasses().isEmpty()) {
        JadxDecompiler decompiler = current.getClasses().get(0).getClassNode().root().getDecompiler();
        // JavaClass.getMethods/getFields/getInnerClasses all load code. Raw nodes do not.
        // Snapshot every identity before code generation can rewrite aliases or members.
        for (JavaClass cls : decompiler.getClassesWithInners()) {
          ClassNode node = cls.getClassNode();
          List<MethodNode> ordered = new ArrayList<>(node.getMethods());
          ordered.sort(Comparator.comparing(MethodNode::getAlias));
          List<MethodSnapshot> methods = ordered.stream().map(method -> {
            String name = method.getAlias();
            String shortId = method.getMethodInfo().getShortId();
            String rawName = method.getMethodInfo().getName();
            if (!shortId.startsWith(rawName + "("))
              throw new IllegalStateException("JADX method ID has no raw-name prefix: " + shortId);
            String descriptor = shortId.substring(rawName.length());
            List<String> bodyAbsenceMarkers = new ArrayList<>();
            if (method.getAccessFlags().isNative()) bodyAbsenceMarkers.add("native_method");
            if (method.getAccessFlags().isAbstract()) bodyAbsenceMarkers.add("abstract_method");
            String signature = name + "(" + method.getArgTypes().stream()
                .map(Object::toString).collect(Collectors.joining(", "))
                + "): " + method.getReturnType().toString();
            return new MethodSnapshot(name, rawName, shortId, List.copyOf(bodyAbsenceMarkers), Map.of(
                "name", name, "signature", signature,
                "dex_descriptor", descriptor,
                "is_constructor", method.isConstructor(), "def_pos", 0));
          }).toList();
          List<Map<String, Object>> fields = node.getFields().stream()
              .sorted(Comparator.comparing(FieldNode::getAlias))
              .map(field -> Map.<String, Object>of("name", field.getAlias(),
                  "type", field.getType().toString(), "def_pos", 0)).toList();
          List<String> inner = node.getInnerClasses().stream().map(ClassNode::getFullName).toList();
          Map<String, Object> summary = Map.of(
              "full_name", cls.getFullName(), "name", cls.getName(),
              "method_count", methods.size(), "field_count", fields.size(),
              "inner_class_count", inner.size(), "inner_classes", inner,
              "methods", methods.stream().map(MethodSnapshot::summary).toList(), "fields", fields);
          index.computeIfAbsent(cls.getFullName(), ignored -> new ArrayList<>())
              .add(new ClassSnapshot(cls, methods, summary));
        }
      }
      classes = Collections.unmodifiableMap(index);
      indexedSession = current;
    }
    String name = string(args, "class_name");
    List<ClassSnapshot> candidates = classes.get(name);
    if (candidates == null) throw new InputFailure("class_name", "Exact class not found: " + name
        + "; use search_android_classes to discover fully qualified names.");
    if (candidates.size() != 1) throw new InputFailure("class_name", "Ambiguous metadata class identity: " + name
        + "; raw identities: " + candidates.stream().map(candidate -> candidate.node().getRawName()).toList());
    return candidates.get(0);
  }

  private List<MethodSnapshot> methods(ClassSnapshot cls, JsonObject args) {
    String name = string(args, "method_name");
    List<MethodSnapshot> result = cls.methods().stream().filter(method -> method.name().equals(name)).toList();
    if (result.isEmpty()) throw new InputFailure("method_name", "Method not found: " + name
        + "; use inspect_android_class to discover available methods.");
    return result;
  }

  private JavaMethod method(ClassSnapshot cls, MethodSnapshot selected) {
    JavaMethod result = cls.node().searchMethodByShortId(selected.shortId());
    if (result == null) throw new IllegalArgumentException("Method identity no longer available: " + selected.shortId());
    return result;
  }

  private JadxSession.SmartCode methodBody(JadxSession current, ClassSnapshot cls,
      MethodSnapshot selected, JavaMethod method) {
    // Access flags belong to the parsed member, before code generation rewrites it.
    // These methods have no Java body; source slicing can include unrelated members.
    if (!selected.bodyAbsenceMarkers().isEmpty())
      return new JadxSession.SmartCode("", "java", false, selected.bodyAbsenceMarkers());
    // Java code generation can fold all or part of <clinit> into field declarations.
    // Its method text cannot establish coverage, even when a static block remains.
    if (selected.shortId().equals("<clinit>()V"))
      return exactMethodSmali(current, cls, selected, List.of("static_initializer_disassembly"));
    String java = current.getMethodSource(method);
    if (java.startsWith("// ERROR:")) throw new IllegalArgumentException(java);
    // The upstream placeholder means only that Java code was omitted, including
    // methods merged into synthetic bridges. Access flags established absence above.
    if (java.isEmpty() || java.equals(
        "// method exists but has no decompiled body (native/abstract)"))
      return exactMethodSmali(current, cls, selected, List.of("java_body_unavailable"));
    List<String> markers = DecompileFailureKt.detectDecompileFailure(java);
    if (markers.stream().anyMatch(DecompileFailureKt.getSTRONG_FAILURE_MARKERS()::contains))
      return exactMethodSmali(current, cls, selected, markers);
    return new JadxSession.SmartCode(
        TextUtilKt.truncateToBytes(java, current.getMaxSourceBytes()), "java", false, markers);
  }

  private JadxSession.SmartCode exactMethodSmali(JadxSession current, ClassSnapshot cls,
      MethodSnapshot selected, List<String> markers) {
    JadxSession.MethodSmali smali = current.getMethodSmali(cls.node(), selected.rawName());
    String block = selectMethodSmali(smali, selected.shortId());
    return new JadxSession.SmartCode(
        TextUtilKt.truncateToBytes(block, current.getMaxSourceBytes()), "smali", true, markers);
  }

  private static String selectMethodSmali(JadxSession.MethodSmali smali, String shortId) {
    if (!smali.getFound())
      throw new IllegalArgumentException("JADX could not disassemble " + shortId
          + (smali.getNote() == null ? "" : ": " + smali.getNote()));
    // Upstream returns every same-name overload, and can return an unterminated
    // trailing block. Match the full original identity before applying output limits.
    List<String> matches = smali.getBlocks().stream().filter(block -> {
      String header = block.lines().findFirst().orElse("").strip();
      return header.startsWith(".method ") && header.endsWith(" " + shortId);
    }).toList();
    if (matches.size() != 1)
      throw new IllegalArgumentException("Disassembly could not establish one selected method: " + shortId);
    String block = matches.get(0);
    if (!block.stripTrailing().endsWith("\n.end method"))
      throw new IllegalArgumentException("Selected method disassembly is incomplete: " + shortId);
    return block;
  }

  // The local transport admits 8 MiB frames. Reserve 1 KiB for the fixed
  // JSON-RPC/CallToolResult envelope and generated numeric request id, and
  // account for JSON text being escaped again inside TextContent.
  private static final int MAX_XREF_TEXT_BYTES = 8 * 1024 * 1024 - 1024;
  private static int escapedJsonBytes(Object value) {
    return JSON.toJson(JSON.toJson(value)).getBytes(StandardCharsets.UTF_8).length;
  }
  private static final class InvokeBudget {
    long remaining;
    InvokeBudget(long remaining) { this.remaining = Math.max(0, remaining); }
    boolean admit(Map<String, Object> site) {
      // Check a conservative two-layer escape bound before serialization.
      long bound = 256;
      for (Object value : site.values())
        if (value instanceof String text) bound += 12L * text.length();
      if (bound > remaining) return false;
      long bytes = escapedJsonBytes(site) - 2L + 1L;
      if (bytes > remaining) return false;
      remaining -= bytes;
      return true;
    }
  }
  private record DirectInvokes(List<Map<String, Object>> sites, boolean exhaustive) {}

  /** Raw DEX invokes within one JADX using method; offsets are code units from its code start. */
  private static DirectInvokes directInvokes(JavaMethod source, MethodInfo target, InvokeBudget budget) {
    MethodNode node = source.getMethodNode();
    ICodeReader code = node.getCodeReader();
    if (code == null) return null;
    List<Map<String, Object>> sites = new ArrayList<>();
    boolean[] exhaustive = {true};
    code.visitInstructions(insn -> {
      insn.decode();
      if (insn.getIndexType() != InsnIndexType.METHOD_REF) return;
      Opcode opcode = insn.getOpcode();
      if (!opcode.name().startsWith("INVOKE_")) return;
      IMethodRef ref = insn.getIndexAsMethod();
      ref.load();
      if (!MethodInfo.fromRef(node.root(), ref).getRawFullId().equals(target.getRawFullId())) return;
      Map<String, Object> site = Map.of(
          "dex_entry", node.getInputFileName(),
          "source_raw_method_id", node.getMethodInfo().getRawFullId(),
          "dex_code_unit_offset", insn.getOffset(),
          "dex_method_index", insn.getIndex(),
          "opcode", opcode.name());
      if (budget.admit(site)) sites.add(site);
      else exhaustive[0] = false;
    });
    return new DirectInvokes(sites, exhaustive[0]);
  }

  private CallToolResult handle(String name, kotlinx.serialization.json.JsonObject input) {
    JsonObject args = JsonParser.parseString(input.toString()).getAsJsonObject();
    if (name.equals("rea_jvm_status")) return json(Map.of(
        "engine_reported_version", BuildInfo.VERSION,
        "max_heap_bytes", Runtime.getRuntime().maxMemory(),
        "available_processors", Runtime.getRuntime().availableProcessors(),
        "java_version", System.getProperty("java.version"),
        "metadata_scope", "parsed_members"));
    JadxSession current = session();
    if (name.equals("list_classes")) {
      List<String> names = current.getClassFqns();
      String query = args.has("query") ? string(args, "query") : "";
      int offset = integer(args, "offset", 0);
      int limit = integer(args, "limit", 200);
      int start = Math.min(offset, names.size());
      int end = start;
      List<String> items;
      if (query.isEmpty()) {
        end = (int) Math.min((long) start + limit, names.size());
        items = names.subList(start, end);
      } else {
        items = new ArrayList<>();
        while (end < names.size() && items.size() < limit) {
          String nameInInventory = names.get(end++);
          if (nameInInventory.contains(query)) items.add(nameInInventory);
        }
      }
      return json(Map.of("total_classes", names.size(), "next_offset", end,
          "scope", "top_level", "offset", offset, "limit", limit,
          "items", items));
    }
    ClassSnapshot cls = selected(args);
    if (name.equals("get_class_summary")) return json(cls.summary());
    if (name.equals("get_method_body")) {
      List<MethodSnapshot> overloads = methods(cls, args);
      int index = integer(args, "overload_index", 0);
      if (index >= overloads.size()) throw new InputFailure("overload_index", "overload_index out of range: " + index);
      JavaMethod method = method(cls, overloads.get(index));
      JadxSession.SmartCode code = methodBody(current, cls, overloads.get(index), method);
      return json(Map.of("class_name", cls.summary().get("full_name"),
          "method_name", overloads.get(index).name(), "full_name", method.getFullName(),
          "dex_descriptor", overloads.get(index).summary().get("dex_descriptor"),
          "overload_index", index, "overload_count", overloads.size(),
          "mode", code.getKind(), "fell_back", code.getFellBack(),
          "markers", code.getMarkers(), "body", code.getText()));
    }
    List<JavaNode> uses;
    String target = string(args, "class_name");
    MethodSnapshot selectedMethod = null;
    int overloadIndex = 0;
    if (name.equals("get_xrefs_to_class")) uses = cls.node().getUseIn();
    else {
      List<MethodSnapshot> overloads = methods(cls, args);
      if (overloads.size() != 1 && !args.has("overload_index"))
        throw new InputFailure("overload_index", "Select one of " + overloads.size() + " method overloads");
      overloadIndex = integer(args, "overload_index", 0);
      if (overloadIndex >= overloads.size())
        throw new InputFailure("overload_index", "overload_index out of range: " + overloadIndex);
      selectedMethod = overloads.get(overloadIndex);
      target += "." + selectedMethod.name();
      uses = method(cls, selectedMethod).getUseIn();
    }
    // REA consumes all references without materializing source line information.
    MethodInfo targetInfo = selectedMethod == null ? null : method(cls, selectedMethod).getMethodNode().getMethodInfo();
    List<Map<String, Object>> items = uses.stream().map(node -> {
      Map<String, Object> item = new LinkedHashMap<>(current.describeUsage(node, false));
      if (targetInfo != null && node instanceof JavaMethod) {
        item.put("direct_invokes", List.of());
        item.put("direct_invokes_exhaustive", false);
      }
      return item;
    }).toList();
    Map<String, Object> result = new LinkedHashMap<>(Map.of("target", target,
        "total", uses.size(), "count", items.size(), "resolve_line", false, "items", items));
    if (selectedMethod != null) {
      result.put("overload_index", overloadIndex);
      result.put("reported_signature", selectedMethod.summary().get("signature"));
    }
    if (targetInfo != null) {
      InvokeBudget budget = new InvokeBudget(MAX_XREF_TEXT_BYTES - escapedJsonBytes(result));
      for (int index = 0; index < uses.size(); index++) {
        if (!(uses.get(index) instanceof JavaMethod source)) continue;
        DirectInvokes invokes = directInvokes(source, targetInfo, budget);
        Map<String, Object> item = items.get(index);
        if (invokes == null) {
          item.remove("direct_invokes");
          item.remove("direct_invokes_exhaustive");
        } else {
          item.put("direct_invokes", invokes.sites());
          item.put("direct_invokes_exhaustive", invokes.exhaustive());
        }
      }
    }
    return json(result);
  }

  public static void main(String[] args) throws Exception {
    PrintStream protocolOut = System.out;
    System.setOut(System.err);
    SessionConfig defaults = new SessionConfig(
        1048576, 0, 90000L, 1, List.of(), List.of(), 64, ResourceMode.FULL);
    SessionHolder holder = new SessionHolder(defaults);
    ServerCapabilities capabilities = new ServerCapabilities(
        new ServerCapabilities.Tools(null), null, null, null, null, null, null, Map.of());
    Server server = new Server(new Implementation("rea-jadx-bridge", "4", null, null, null),
        new ServerOptions(capabilities), "", ignored -> Unit.INSTANCE);
    SessionToolsKt.registerSessionTools(server, holder);
    ManifestToolsKt.registerManifestTools(server, holder);
    ClassToolsKt.registerClassTools(server, holder);
    MethodToolsKt.registerMethodTools(server, holder);
    XrefToolsKt.registerXrefTools(server, holder);
    ReaJadxBridge bridge = new ReaJadxBridge(holder);
    Tool loadTool = server.getTools().get("load_apk").getTool();
    server.removeTool("load_apk");
    server.addTool(loadTool, (connection, request, continuation) ->
        bridge.load(request.getArguments(), defaults, continuation));
    Set<String> consumed = Set.of("load_apk", "get_app_info", "get_android_manifest",
        "list_classes", "get_class_summary", "get_method_body",
        "get_xrefs_to_class", "get_xrefs_to_method");
    for (String name : new ArrayList<>(server.getTools().keySet()))
      if (!consumed.contains(name)) server.removeTool(name);
    Tool diagnostics = new Tool("rea_jvm_status",
        new ToolSchema(null, new kotlinx.serialization.json.JsonObject(Map.of()), List.of(), null),
        "Observed worker JVM and metadata scope", null, null, null, null, null, null);
    server.addTool(diagnostics, (connection, request, continuation) -> bridge.handle("rea_jvm_status", request.getArguments()));
    for (String name : List.of("list_classes", "get_class_summary",
        "get_method_body", "get_xrefs_to_class", "get_xrefs_to_method")) {
      Tool tool = server.getTools().get(name).getTool();
      server.removeTool(name);
      List<String> fields = switch (name) {
        case "list_classes" -> List.of("offset", "limit");
        case "get_method_body" -> List.of("class_name", "method_name", "overload_index");
        case "get_xrefs_to_method" -> List.of("class_name", "method_name", "overload_index");
        default -> List.of("class_name");
      };
      Map<String, kotlinx.serialization.json.JsonElement> properties = new LinkedHashMap<>();
      for (String field : fields) properties.put(field, tool.getInputSchema().getProperties().get(field));
      if (name.equals("list_classes")) properties.put("query",
          new kotlinx.serialization.json.JsonObject(Map.of(
              "type", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("string"))));
      String description = switch (name) {
        case "list_classes" -> "Pages of case-sensitive matching top-level class names; offset and next_offset are inventory positions, limit bounds matching rows. Omitted or empty query inventories all names.";
        case "get_class_summary" -> "Parsed member metadata for one exact class name; no source generation.";
        case "get_method_body" -> "Source for an exact class and stable same-name overload index; static initializers use smali to preserve folded field initialization.";
        default -> "Complete static using-node inventory for an exact class or selected method overload; one node may contain multiple invoke instructions, and source lines are unresolved.";
      };
      Tool narrowed = new Tool(name, new ToolSchema(null, new kotlinx.serialization.json.JsonObject(properties),
          tool.getInputSchema().getRequired(), null), description, null, null, null, null, null, null);
      server.addTool(narrowed, (connection, request, continuation) -> {
        try { return bridge.handle(name, request.getArguments()); }
        catch (InputFailure error) { return text(JSON.toJson(Map.of(
            "kind", "invalid-input", "field", error.field, "message", error.getMessage())), true); }
        catch (IllegalArgumentException error) { return text(error.getMessage(), true); }
      });
    }
    CountDownLatch done = new CountDownLatch(1);
    server.onClose(() -> { done.countDown(); return Unit.INSTANCE; });
    StdioServerTransport transport = new StdioServerTransport(
        CoreKt.buffered(JvmCoreKt.asSource(System.in)),
        CoreKt.buffered(JvmCoreKt.asSink(protocolOut)));
    transport.onClose(() -> { done.countDown(); return Unit.INSTANCE; });
    ServerSession connection = null;
    try {
      connection = BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
          (scope, continuation) -> server.createSession(transport, continuation));
      done.await();
    } finally {
      try {
        if (connection != null) {
          ServerSession connected = connection;
          // Unsubscribe the connection before the SDK joins its notification service.
          BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
              (scope, continuation) -> connected.close(continuation));
        }
      } finally {
        try {
          BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
              (scope, continuation) -> server.close(continuation));
        } finally {
          BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
              (scope, continuation) -> holder.unload(continuation));
        }
      }
    }
  }
}
