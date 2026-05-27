"""MCP tool definitions — Windows remote operations via WinRM."""

import base64
import logging
from typing import Any

from fastmcp import Context, FastMCP

from agent.session_manager import SessionRegistry

logger = logging.getLogger("win-mcp.tools")

VALID_ENCODINGS = frozenset(
    {"ascii", "bigendianunicode", "default", "oem", "unicode", "utf7", "utf8", "utf32"}
)

EVENT_LEVELS: dict[str, str] = {
    "critical": "1",
    "error": "2",
    "warning": "3",
    "info": "4",
}


def _ps_escape(value: str) -> str:
    """Escape a value for embedding in a PowerShell single-quoted string."""
    return value.replace("'", "''")


def register_tools(mcp: FastMCP, sm: SessionRegistry) -> None:
    async def _ensure_ad_password(ctx: Context) -> dict[str, Any] | None:
        if sm.has_cached_password():
            return None

        username = sm.current_username()
        try:
            result = await ctx.elicit(
                message=(
                    f"Enter your AD password for {username}.\n"
                    "It is cached only in MCP server memory with an idle TTL and is never logged."
                ),
                response_type=str,
            )
            if result.action != "accept":
                return {"status": "cancelled", "message": "AD password entry cancelled"}
        except Exception:
            return {"error": "Elicitation unavailable - cannot prompt for AD password"}

        password = result.data if hasattr(result, "data") and result.data else ""
        if not password:
            return {"error": "No AD password provided"}

        sm.cache_password(str(password))
        return None

    # ==================================================================
    # Session lifecycle
    # ==================================================================

    @mcp.tool()
    async def connect(host: str, ctx: Context, port: int = 5985) -> dict[str, Any]:
        """REQUIRED FIRST STEP — connect before calling any other tool. Authenticates via WinRM/NTLM after eliciting your AD password once per cached session; the password is stored only in server memory with an idle TTL and never appears in tool responses or logs. Returns a session_id you must pass to every subsequent tool call, plus computer name, OS version, and last boot time for immediate triage context.

        Args:
            host: Hostname or IP address (e.g. 'web-server-01').
            port: WinRM HTTP port (default 5985).
        """
        auth_error = await _ensure_ad_password(ctx)
        if auth_error is not None:
            return auth_error
        return sm.connect(host, port)

    @mcp.tool()
    def disconnect(session_id: str) -> dict[str, Any]:
        """Close a WinRM session when you are done. Always disconnect when finished — sessions are not automatically cleaned up. Call list_sessions first if you need to find the session_id.

        Args:
            session_id: Session ID returned by connect.
        """
        return sm.disconnect(session_id)

    @mcp.tool()
    def list_sessions() -> dict[str, Any]:
        """List all active WinRM sessions with host, connection time, last used time, and command count. Use this to find session IDs or check if you are already connected to a host."""
        return sm.list_sessions()

    # ==================================================================
    # Filesystem — read-only
    # ==================================================================

    @mcp.tool()
    def list_directory(session_id: str, path: str) -> dict[str, Any]:
        """List files and directories at the given path, showing Mode, LastWriteTime, Length, and Name (max 200 entries). Returns tabular text output. Use this to explore directory structure; use find_files to search recursively by pattern instead.

        Args:
            session_id: Session ID from connect.
            path: Absolute directory path (e.g. 'C:\\Users' or 'D:\\Logs').
        """
        safe = _ps_escape(path)
        cmd = (
            "Get-ChildItem -LiteralPath '" + safe + "' -Force -ErrorAction Stop "
            "| Select-Object -First 200 Mode, LastWriteTime, Length, Name "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="list_directory")

    @mcp.tool()
    def find_files(
        session_id: str,
        path: str,
        pattern: str,
        max_depth: int = 5,
        include_size: bool = True,
    ) -> dict[str, Any]:
        """Recursively search for files matching a wildcard pattern, returning FullName, Size, and LastWriteTime (max 100 results). Finds files only, not directories — use list_directory to browse folders. Returns tabular text output.

        Args:
            session_id: Session ID from connect.
            path: Root directory to search from.
            pattern: Wildcard pattern (e.g. '*.log', '*.config', 'server.xml').
            max_depth: Recursion depth limit (default 5, max 10).
            include_size: Include file size in output (default true).
        """
        safe_path = _ps_escape(path)
        safe_pattern = _ps_escape(pattern)
        depth = max(0, min(max_depth, 10))
        cols = "FullName, Length, LastWriteTime" if include_size else "FullName, LastWriteTime"
        cmd = (
            "Get-ChildItem -Path '" + safe_path + "' -Recurse "
            "-Filter '" + safe_pattern + "' "
            "-Depth " + str(depth) + " -ErrorAction SilentlyContinue "
            "| Select-Object -First 100 " + cols + " "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="find_files")

    @mcp.tool()
    def read_file(
        session_id: str,
        path: str,
        start_line: int = 1,
        end_line: int = 200,
        tail: bool = False,
        encoding: str = "UTF8",
    ) -> dict[str, Any]:
        """Read file contents with numbered lines (max 500 lines per call). Returns plain text with '     1|line content' format. Two modes: (1) Range mode (default): reads lines start_line through end_line from the top. (2) Tail mode (tail=True): reads the last N lines from end of file where N=end_line — fast even on huge files, ideal for checking recent log entries.

        Args:
            session_id: Session ID from connect.
            path: Absolute file path.
            start_line: First line to return (1-based, default 1). Ignored when tail=True.
            end_line: Range mode: last line number to return (default 200). Tail mode: number of lines from the end to return.
            tail: When true, read last N lines instead of a range from start. Use for logs.
            encoding: File encoding (default UTF8). Use 'Unicode' for UTF-16 legacy files.
        """
        enc_lookup = {e: e for e in VALID_ENCODINGS}
        enc_key = encoding.strip().lower()
        if enc_key not in enc_lookup:
            return {"error": f"Invalid encoding '{encoding}'. Valid: {', '.join(sorted(VALID_ENCODINGS))}"}
        enc = enc_lookup[enc_key]

        safe = _ps_escape(path)

        if tail:
            count = max(1, min(end_line, 500))
            cmd = (
                "$lines = @(Get-Content -LiteralPath '" + safe + "' "
                "-Tail " + str(count) + " -Encoding " + enc + " -ErrorAction Stop); "
                "$n = 1; "
                "$lines | ForEach-Object { '{0,6}|{1}' -f ($n++), $_ }; "
                "Write-Output (\"--- tail: last $($lines.Count) lines ---\")"
            )
        else:
            if start_line < 1:
                start_line = 1
            if end_line < start_line:
                return {"error": "end_line must be >= start_line"}
            if end_line - start_line + 1 > 500:
                end_line = start_line + 499

            skip = start_line - 1
            cmd = (
                "$lines = @(Get-Content -LiteralPath '" + safe + "' "
                "-TotalCount " + str(end_line) + " -Encoding " + enc + " -ErrorAction Stop); "
                "$n = " + str(start_line) + "; "
                "$lines | Select-Object -Skip " + str(skip) + " | "
                "ForEach-Object { '{0,6}|{1}' -f ($n++), $_ }; "
                "Write-Output (\"--- lines " + str(start_line) + " to "
                + str(end_line) + ", read $($lines.Count) lines ---\")"
            )
        return sm.run_ps(session_id, cmd, tool_name="read_file")

    @mcp.tool()
    def search_file_content(
        session_id: str,
        path: str,
        pattern: str,
        file_filter: str = "*",
        max_results: int = 50,
        context_lines: int = 0,
        modified_after_hours: int = 0,
    ) -> dict[str, Any]:
        """Search for literal text inside files, like grep. Pass a single file path to search that file, or a directory path to search recursively across files matching file_filter. Pattern is literal only — no regex or wildcards in the search text.

        EFFICIENCY GUIDANCE — READ BEFORE CALLING ON A DIRECTORY:
        Recursive searches against large directories can scan gigabytes of files and time out or return noisy stale matches. To keep calls fast and relevant you MUST narrow the search BEFORE invoking this tool:

        1. SCOPE THE PATH as tightly as possible. Prefer a specific subdirectory over a broad root. If you do not know the layout, call list_directory first to identify the right subfolder.
        2. ALWAYS set modified_after_hours when path is a directory and you are investigating recent activity. Typical values:
           - Active incident / "happening now": 1–6 hours
           - Today's issue: 24 hours
           - Recent regression: 72–168 hours
           Only use 0 (all files) when you have an explicit reason to inspect historical files.
        3. USE A PRECISE file_filter to exclude rotated archives and unrelated file types. Prefer the most specific pattern that still covers the likely source.
        4. PICK A DISCRIMINATING pattern. Literal, distinctive strings (exception class names, error codes, correlation IDs, stack frame signatures) return useful results; generic words like 'error' or 'failed' flood the cap and hide real matches. If you need multiple variants, run several targeted searches instead of one broad one.
        5. KEEP max_results modest (default 50 is usually right). If you hit the cap, tighten the filters above rather than raising the cap — truncated results mean the search was too broad.
        6. USE context_lines sparingly (2–3) only when you need surrounding log lines to interpret a match; 0 is faster and sufficient for counting/locating hits.
        7. FOR A KNOWN SINGLE FILE, pass the file path directly instead of its parent directory — this skips directory enumeration entirely.

        If you are unsure how big a directory is, call find_files or list_directory first to gauge volume, then come back with scoped arguments.

        Args:
            session_id: Session ID from connect.
            path: File path, or directory to search recursively. Prefer the narrowest subdirectory that could contain the match.
            pattern: Exact text to search for (literal match, no regex). Choose a distinctive string to avoid noisy results.
            file_filter: Wildcard filter when path is a directory (e.g. '*.log', 'error*.log', '*.xml'). Default '*' scans everything — override it.
            max_results: Max matching lines to return (default 50, max 100). If you hit this cap, tighten filters instead of raising it.
            context_lines: Lines before and after each match, like grep -C (default 0, max 10). Use 2–3 only when needed.
            modified_after_hours: Only search files changed within this many hours (0 = all files).
        """
        safe_path = _ps_escape(path)
        safe_pattern = _ps_escape(pattern)
        safe_filter = _ps_escape(file_filter)
        cap = max(1, min(max_results, 100))
        ctx = max(0, min(context_lines, 10))
        ctx_arg = " -Context " + str(ctx) + "," + str(ctx) if ctx > 0 else ""

        time_filter = ""
        if modified_after_hours > 0:
            time_filter = (
                "| Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-"
                + str(modified_after_hours) + ") } "
            )

        if ctx > 0:
            fmt_file = "| Out-String -Width 300"
            fmt_single = "| Out-String -Width 300"
        else:
            fmt_file = '| ForEach-Object { "$($_.Path):$($_.LineNumber)|$($_.Line)" }'
            fmt_single = '| ForEach-Object { "$($_.LineNumber)|$($_.Line)" }'

        cmd = (
            "$t = Get-Item -LiteralPath '" + safe_path + "' -ErrorAction Stop; "
            "if ($t.PSIsContainer) { "
            "Get-ChildItem -Path '" + safe_path + "' -Recurse -File "
            "-Filter '" + safe_filter + "' -ErrorAction SilentlyContinue "
            + time_filter +
            "| Select-String -Pattern '" + safe_pattern + "' -SimpleMatch"
            + ctx_arg + " -ErrorAction SilentlyContinue "
            "| Select-Object -First " + str(cap) + " "
            + fmt_file +
            " } else { "
            "Select-String -LiteralPath '" + safe_path + "' "
            "-Pattern '" + safe_pattern + "' -SimpleMatch"
            + ctx_arg + " -ErrorAction Stop "
            "| Select-Object -First " + str(cap) + " "
            + fmt_single +
            " }"
        )
        return sm.run_ps(session_id, cmd, tool_name="search_file_content")

    @mcp.tool()
    def file_info(session_id: str, path: str) -> dict[str, Any]:
        """Get metadata for a single file or directory: size in bytes/KB, created/modified/accessed timestamps, and attributes. Returns a JSON object. Use this to check file size before reading, or to verify a path exists.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to file or directory.
        """
        safe = _ps_escape(path)
        cmd = (
            "Get-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop "
            "| Select-Object FullName, "
            "@{N='SizeBytes';E={$_.Length}}, "
            "@{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}}, "
            "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "@{N='Accessed';E={$_.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "Attributes "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="file_info")

    # ==================================================================
    # System diagnostics — read-only
    # ==================================================================

    @mcp.tool()
    def get_event_log(
        session_id: str,
        log_name: str = "System",
        level: str = "Error",
        hours_back: int = 24,
        source: str = "",
        count: int = 25,
    ) -> dict[str, Any]:
        """Read Windows Event Log — the primary diagnostic source for crashes, service failures, auth errors, and disk warnings. Setting level includes that level AND all higher severities: 'Warning' returns Warning+Error+Critical, 'Error' returns Error+Critical. Check Application log for app crashes, System for OS/driver issues, Security for auth failures.

        Args:
            session_id: Session ID from connect.
            log_name: Event log name: System (default), Application, or Security.
            level: Severity threshold — includes this level and above. Critical, Error (default), Warning, or Info.
            hours_back: How far back to search in hours (default 24, max 720).
            source: Filter by provider name (e.g. '*SQL*', 'Microsoft-Windows-Security-SPP'). Wildcard OK.
            count: Max events to return (default 25, max 100).
        """
        safe_log = _ps_escape(log_name)
        cap = max(1, min(count, 100))
        hrs = max(1, min(hours_back, 720))

        level_key = level.strip().lower()
        level_nums: list[str] = []
        for lname, lnum in EVENT_LEVELS.items():
            level_nums.append(lnum)
            if lname == level_key:
                break
        if not level_nums:
            level_nums = ["1", "2"]
        levels_str = ",".join(level_nums)

        source_filter = ""
        if source.strip():
            safe_source = _ps_escape(source.strip())
            source_filter = (
                "| Where-Object { $_.ProviderName -like '" + safe_source + "' } "
            )

        cmd = (
            "Get-WinEvent -FilterHashtable @{LogName='" + safe_log + "'; "
            "Level=" + levels_str + "; "
            "StartTime=(Get-Date).AddHours(-" + str(hrs) + ")} "
            "-MaxEvents " + str(cap * 3) + " -ErrorAction SilentlyContinue "
            + source_filter +
            "| Select-Object -First " + str(cap) + " "
            "| ForEach-Object { "
            "\"$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) "
            "[$($_.LevelDisplayName)] ($($_.ProviderName)) ID:$($_.Id)\"; "
            "\"  $($_.Message.Substring(0,[Math]::Min($_.Message.Length,400)))\"; "
            "\"---\" }"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_event_log")

    @mcp.tool()
    def get_services(
        session_id: str,
        name_filter: str = "",
        status_filter: str = "All",
        detail: bool = False,
    ) -> dict[str, Any]:
        """List Windows services. Summary mode (default) returns a quick tabular overview with Name, Status, StartType, DisplayName. Detail mode (detail=True) returns structured JSON per service with full inspection data: binary path, working directory, logon account, PID, memory, delayed auto-start, exit codes, dependencies, description, and recovery actions. Use summary to find services, then detail to inspect before restarting.

        Args:
            session_id: Session ID from connect.
            name_filter: Wildcard filter on Name or DisplayName (e.g. '*sql*', '*jboss*', 'AQS').
            status_filter: Running, Stopped, or All (default All).
            detail: Deep inspection mode returning JSON. Shows binary_path, working_directory, service_account, PID, memory_mb, delayed_auto_start, win32_exit_code, service_exit_code, dependencies, depended_by, description, and recovery actions. Best used with a name_filter to inspect specific services.
        """
        where_clauses: list[str] = []

        sf = status_filter.strip().lower()
        if sf in ("running", "stopped"):
            where_clauses.append("$_.Status -eq '" + sf.capitalize() + "'")

        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            where_clauses.append(
                "($_.Name -like '" + safe_nf + "' -or $_.DisplayName -like '" + safe_nf + "')"
            )

        where = ""
        if where_clauses:
            where = "| Where-Object { " + " -and ".join(where_clauses) + " } "

        if not detail:
            cmd = (
                "Get-Service -ErrorAction SilentlyContinue "
                + where +
                "| Sort-Object Status, Name "
                "| Select-Object Name, Status, StartType, DisplayName "
                "| Format-Table -AutoSize | Out-String -Width 300"
            )
        else:
            cmd = (
                "@(Get-Service -ErrorAction SilentlyContinue "
                + where +
                "| ForEach-Object { "
                "$svc = $_; "
                "$wmi = Get-CimInstance Win32_Service -Filter \"Name='$($svc.Name)'\" -ErrorAction SilentlyContinue; "
                "$proc = if($wmi.ProcessId -and $wmi.ProcessId -gt 0)"
                "{Get-Process -Id $wmi.ProcessId -ErrorAction SilentlyContinue}else{$null}; "
                "$binPath = if($wmi.PathName){$wmi.PathName -replace '\"',''}else{''}; "
                "$workDir = if($binPath){Split-Path -Parent ($binPath -split ' ')[0]}else{''}; "
                "$delayed = (Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($svc.Name)\" "
                "-Name 'DelayedAutostart' -ErrorAction SilentlyContinue).DelayedAutostart; "
                "$rec = @(sc.exe qfailure $svc.Name 2>$null); "
                "$r1 = ($rec | Select-String 'RESET_PERIOD' | ForEach-Object { ($_ -split ':',2)[1].Trim() }); "
                "$a1 = ($rec | Select-String 'FAILURE_ACTIONS' | ForEach-Object { ($_ -split ':',2)[1].Trim() }); "
                "[PSCustomObject]@{"
                "name=$svc.Name; "
                "display_name=$svc.DisplayName; "
                "status=[string]$svc.Status; "
                "start_type=[string]$svc.StartType; "
                "delayed_auto_start=if($delayed -eq 1){$true}else{$false}; "
                "binary_path=$wmi.PathName; "
                "working_directory=$workDir; "
                "service_account=$wmi.StartName; "
                "pid=if($wmi.ProcessId){$wmi.ProcessId}else{$null}; "
                "memory_mb=if($proc){[math]::Round($proc.WorkingSet64/1MB,1)}else{$null}; "
                "win32_exit_code=$wmi.ExitCode; "
                "service_exit_code=$wmi.ServiceSpecificExitCode; "
                "dependencies=@($svc.ServicesDependedOn | Select-Object -ExpandProperty Name); "
                "depended_by=@($svc.DependentServices | Select-Object -ExpandProperty Name); "
                "description=$wmi.Description; "
                "recovery_reset_s=$r1; "
                "recovery_actions=$a1"
                "}"
                "}) | ConvertTo-Json -Compress -Depth 3"
            )
        return sm.run_ps(session_id, cmd, tool_name="get_services")

    @mcp.tool()
    def list_processes(
        session_id: str,
        name_filter: str = "",
        sort_by: str = "Memory",
        top: int = 30,
    ) -> dict[str, Any]:
        """List running processes showing PID, name, CPU seconds, memory in MB, handle count, and start time. Use to identify resource hogs, confirm an application is running, or check for hung processes. Returns tabular text sorted descending by the chosen metric.

        Args:
            session_id: Session ID from connect.
            name_filter: Wildcard on process name (e.g. 'java*', 'w3wp*', 'sqlservr*').
            sort_by: Sort by CPU or Memory (default Memory).
            top: Number of processes to show (default 30, max 100).
        """
        cap = max(1, min(top, 100))
        sort_prop = "WorkingSet64" if sort_by.strip().lower() != "cpu" else "CPU"

        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.ProcessName -like '" + safe_nf + "' } "

        cmd = (
            "Get-Process -ErrorAction SilentlyContinue "
            + name_where +
            "| Sort-Object " + sort_prop + " -Descending "
            "| Select-Object -First " + str(cap) + " "
            "Id, ProcessName, "
            "@{N='CPU_s';E={[math]::Round($_.CPU,1)}}, "
            "@{N='Mem_MB';E={[math]::Round($_.WorkingSet64/1MB,1)}}, "
            "@{N='Handles';E={$_.HandleCount}}, "
            "@{N='Started';E={if($_.StartTime){$_.StartTime.ToString('yyyy-MM-dd HH:mm')}else{'N/A'}}} "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="list_processes")

    @mcp.tool()
    def get_system_info(session_id: str) -> dict[str, Any]:
        """Get full system overview in one call — OS version, uptime, last boot time, total/free RAM, CPU count, domain, and timezone. Call this first after connect to establish triage context. Returns a JSON object.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "$os = Get-CimInstance Win32_OperatingSystem; "
            "$cs = Get-CimInstance Win32_ComputerSystem; "
            "[PSCustomObject]@{"
            "ComputerName=$env:COMPUTERNAME; "
            "OS=$os.Caption; "
            "Version=$os.Version; "
            "BuildNumber=$os.BuildNumber; "
            "LastBoot=$os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'); "
            "Uptime=((Get-Date)-$os.LastBootUpTime).ToString('d\\.hh\\:mm\\:ss'); "
            "TotalRAM_GB=[math]::Round($cs.TotalPhysicalMemory/1GB,1); "
            "FreeRAM_GB=[math]::Round($os.FreePhysicalMemory/1MB,1); "
            "CPUs=$cs.NumberOfLogicalProcessors; "
            "Domain=$cs.Domain; "
            "TimeZone=(Get-TimeZone).Id"
            "} | ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_system_info")

    @mcp.tool()
    def get_disk_space(session_id: str) -> dict[str, Any]:
        """Get disk space for all fixed drives — DeviceID, Total_GB, Free_GB, and Used_Pct. Disk full is a top-5 cause of production incidents. Returns tabular text, one row per drive.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" "
            "| Select-Object DeviceID, "
            "@{N='Total_GB';E={[math]::Round($_.Size/1GB,1)}}, "
            "@{N='Free_GB';E={[math]::Round($_.FreeSpace/1GB,1)}}, "
            "@{N='Used_Pct';E={[math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100,1)}} "
            "| Format-Table -AutoSize | Out-String -Width 200"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_disk_space")

    @mcp.tool()
    def get_perf_snapshot(
        session_id: str,
        samples: int = 3,
        interval_sec: int = 2,
        process_filter: str = "",
    ) -> dict[str, Any]:
        """Capture a performance counter snapshot — CPU, memory, disk I/O, network, TCP connections, and optionally per-process stats for filtered processes. Samples are averaged to smooth out single-second noise. Use this to answer "is the server healthy?", "is it CPU-bound?", "is disk thrashing?", or "how much memory is Java using?". Returns a structured JSON object. Takes (samples × interval_sec) seconds to complete.

        Args:
            session_id: Session ID from connect.
            samples: Number of samples to average (default 3, max 10). More samples = smoother data but slower.
            interval_sec: Seconds between samples (default 2, max 10).
            process_filter: Wildcard filter for per-process counters (e.g. 'java*', 'w3wp*', 'sqlservr*'). If empty, per-process section is omitted for speed.
        """
        cap_samples = max(1, min(samples, 10))
        cap_interval = max(1, min(interval_sec, 10))

        proc_block = "$procData = @(); "
        if process_filter.strip():
            safe_pf = _ps_escape(process_filter.strip())
            proc_block = (
                "try { "
                "$pc = (Get-Counter -Counter @("
                "'\\Process(" + safe_pf + ")\\% Processor Time',"
                "'\\Process(" + safe_pf + ")\\Working Set',"
                "'\\Process(" + safe_pf + ")\\Handle Count',"
                "'\\Process(" + safe_pf + ")\\Thread Count',"
                "'\\Process(" + safe_pf + ")\\IO Read Bytes/sec',"
                "'\\Process(" + safe_pf + ")\\IO Write Bytes/sec'"
                ") -SampleInterval " + str(cap_interval) + " "
                "-MaxSamples " + str(cap_samples) + " "
                "-ErrorAction Stop).CounterSamples; "
                "$procData = @($pc | Group-Object InstanceName | ForEach-Object { "
                "$g = $_.Group; "
                "$cn = $_.Name; "
                "function ga($p,$g){$v=($g|Where-Object{$_.Path-like $p}|Measure-Object CookedValue -Average).Average;if($v){$v}else{0}} "
                "[PSCustomObject]@{ "
                "name=$cn; "
                "cpu_pct=[math]::Round((ga '*% processor time' $g),1); "
                "mem_mb=[math]::Round((ga '*working set' $g)/1MB,1); "
                "handles=[int](ga '*handle count' $g); "
                "threads=[int](ga '*thread count' $g); "
                "io_read_kbs=[math]::Round((ga '*io read*' $g)/1KB,1); "
                "io_write_kbs=[math]::Round((ga '*io write*' $g)/1KB,1)"
                "}})"
                "} catch { $procData = @() }; "
            )

        cmd = (
            "$cs = (Get-Counter -Counter @("
            "'\\Processor(_Total)\\% Processor Time',"
            "'\\Processor(_Total)\\% Privileged Time',"
            "'\\System\\Processor Queue Length',"
            "'\\Memory\\Available MBytes',"
            "'\\Memory\\% Committed Bytes In Use',"
            "'\\Memory\\Pages/sec',"
            "'\\PhysicalDisk(_Total)\\% Disk Time',"
            "'\\PhysicalDisk(_Total)\\Avg. Disk Queue Length',"
            "'\\PhysicalDisk(_Total)\\Disk Read Bytes/sec',"
            "'\\PhysicalDisk(_Total)\\Disk Write Bytes/sec',"
            "'\\Network Interface(*)\\Bytes Total/sec',"
            "'\\TCPv4\\Connections Established',"
            "'\\System\\Threads',"
            "'\\Process(_Total)\\Handle Count'"
            ") -SampleInterval " + str(cap_interval) + " "
            "-MaxSamples " + str(cap_samples) + " "
            "-ErrorAction Stop).CounterSamples; "
            "function av($p){[math]::Round(($cs|Where-Object{$_.Path-like $p}"
            "|Measure-Object CookedValue -Average).Average,2)} "
            + proc_block +
            "$r = [ordered]@{"
            "timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss');"
            "samples=" + str(cap_samples) + ";"
            "interval_sec=" + str(cap_interval) + ";"
            "cpu=[ordered]@{"
            "total_pct=av '*processor time';"
            "kernel_pct=av '*privileged time';"
            "queue_length=av '*processor queue*'"
            "};"
            "memory=[ordered]@{"
            "available_mb=av '*available mbytes';"
            "committed_pct=av '*committed*';"
            "pages_per_sec=av '*pages/sec'"
            "};"
            "disk=[ordered]@{"
            "busy_pct=av '*% disk time';"
            "queue_length=av '*disk queue*';"
            "read_mbs=[math]::Round((av '*disk read bytes*')/1MB,2);"
            "write_mbs=[math]::Round((av '*disk write bytes*')/1MB,2)"
            "};"
            "network=[ordered]@{"
            "throughput_mbs=[math]::Round((av '*bytes total/sec')/1MB,2);"
            "tcp_established=[int](av '*connections established')"
            "};"
            "system=[ordered]@{"
            "total_threads=[int](av '*\\system\\threads');"
            "total_handles=[int](av '*\\handle count')"
            "}"
            "}; "
            "if($procData.Count -gt 0){$r['processes']=@($procData)}; "
            "$r | ConvertTo-Json -Depth 3 -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_perf_snapshot")

    @mcp.tool()
    def test_network(
        session_id: str,
        target: str,
        port: int = 0,
    ) -> dict[str, Any]:
        """Test network connectivity FROM the remote Windows host's perspective. With port=0 sends 3 ICMP pings (tabular text). With port>0 tests TCP connectivity and returns JSON with TcpTestSucceeded boolean. Note: TCP port tests can take 20-35 seconds if the port is blocked. Common ports: 1433 SQL, 5985 WinRM, 443 HTTPS, 3389 RDP, 8080 HTTP.

        Args:
            session_id: Session ID from connect.
            target: Hostname or IP to test connectivity to.
            port: TCP port to test. Set 0 for ICMP ping (default), or a port number for TCP test.
        """
        safe_target = _ps_escape(target)

        if port > 0:
            cmd = (
                "$r = Test-NetConnection -ComputerName '" + safe_target + "' "
                "-Port " + str(port) + " -WarningAction SilentlyContinue; "
                "[PSCustomObject]@{"
                "Target=$r.ComputerName; "
                "RemoteAddress=[string]$r.RemoteAddress; "
                "Port=$r.RemotePort; "
                "TcpTestSucceeded=$r.TcpTestSucceeded; "
                "RTT_ms=$r.PingReplyDetails.RoundtripTime"
                "} | ConvertTo-Json -Compress"
            )
        else:
            cmd = (
                "Test-Connection -ComputerName '" + safe_target + "' "
                "-Count 3 -ErrorAction Stop "
                "| Select-Object "
                "@{N='Target';E={$_.Address}}, "
                "@{N='RTT_ms';E={$_.ResponseTime}}, "
                "@{N='TTL';E={$_.TimeToLive}} "
                "| Format-Table -AutoSize | Out-String -Width 200"
            )
        return sm.run_ps(session_id, cmd, tool_name="test_network")

    @mcp.tool()
    def get_registry(
        session_id: str,
        key: str,
        value_name: str = "",
    ) -> dict[str, Any]:
        """Read a registry key or specific value (read-only). Returns JSON. Use to check service configurations, installed software versions, TLS/crypto settings, or feature flags. Pass value_name to read one value, or omit it to dump all values under the key.

        Args:
            session_id: Session ID from connect.
            key: Registry path. Use 'HKLM:\\' prefix (e.g. 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'). Also accepts HKEY_LOCAL_MACHINE format.
            value_name: Specific value name to read (e.g. 'ProductName'). If empty, returns all values under the key.
        """
        k = key.strip()
        if k.upper().startswith("HKEY_"):
            k = "Registry::" + k

        safe_key = _ps_escape(k)

        if value_name.strip():
            safe_val = _ps_escape(value_name.strip())
            cmd = (
                "Get-ItemProperty -Path '" + safe_key + "' "
                "-Name '" + safe_val + "' -ErrorAction Stop "
                "| Select-Object -Property '" + safe_val + "' "
                "| ConvertTo-Json -Compress"
            )
        else:
            cmd = (
                "Get-ItemProperty -Path '" + safe_key + "' -ErrorAction Stop "
                "| Select-Object * -ExcludeProperty PS* "
                "| ConvertTo-Json -Compress"
            )
        return sm.run_ps(session_id, cmd, tool_name="get_registry")

    @mcp.tool()
    def get_certificates(
        session_id: str,
        store: str = "LocalMachine",
        days_until_expiry: int = 0,
    ) -> dict[str, Any]:
        """List certificates from the Personal (My) certificate store, sorted by days until expiry. Shows Subject, Expires date, DaysLeft, and Thumbprint. Cert expiry is a top cause of silent outages — set days_until_expiry to filter for certs expiring soon. Only checks the 'My' (Personal) store, not Root or CA stores.

        Args:
            session_id: Session ID from connect.
            store: LocalMachine (default) or CurrentUser.
            days_until_expiry: Only show certs expiring within this many days (0 = show all certs).
        """
        store_map = {"localmachine": "LocalMachine", "currentuser": "CurrentUser"}
        st = store_map.get(store.strip().lower())
        if not st:
            return {"error": "store must be 'LocalMachine' or 'CurrentUser'"}

        expiry_filter = ""
        if days_until_expiry > 0:
            expiry_filter = (
                "| Where-Object { $_.NotAfter -lt (Get-Date).AddDays("
                + str(days_until_expiry) + ") } "
            )

        cmd = (
            "Get-ChildItem -Path 'Cert:\\" + st + "\\My' -ErrorAction Stop "
            + expiry_filter +
            "| Select-Object "
            "@{N='Subject';E={$_.Subject.Substring(0,[Math]::Min($_.Subject.Length,80))}}, "
            "@{N='Expires';E={$_.NotAfter.ToString('yyyy-MM-dd')}}, "
            "@{N='DaysLeft';E={[math]::Round(($_.NotAfter-(Get-Date)).TotalDays)}}, "
            "Thumbprint "
            "| Sort-Object DaysLeft "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_certificates")

    @mcp.tool()
    def get_network_config(session_id: str) -> dict[str, Any]:
        """Get network adapter configuration — interface name, status (Up/Down), IPv4 address, default gateway, and DNS servers for each NIC. Essential for network triage: confirms IP assignment, DNS resolution, and gateway reachability. Returns tabular text.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "Get-NetIPConfiguration -ErrorAction SilentlyContinue "
            "| Select-Object InterfaceAlias, "
            "@{N='Status';E={$_.NetAdapter.Status}}, "
            "@{N='IPv4';E={($_.IPv4Address.IPAddress) -join ','}}, "
            "@{N='Gateway';E={($_.IPv4DefaultGateway.NextHop) -join ','}}, "
            "@{N='DNS';E={($_.DNSServer.ServerAddresses) -join ','}} "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_network_config")

    # ==================================================================
    # Environment, tasks, users, permissions — read-only
    # ==================================================================

    @mcp.tool()
    def get_environment_variables(
        session_id: str,
        name_filter: str = "",
        scope: str = "Machine",
    ) -> dict[str, Any]:
        """Get environment variables. Shows name and value for the selected scope. Use to check JAVA_HOME, PATH, service-specific env vars, or any system/user configuration. Returns tabular text.

        Args:
            session_id: Session ID from connect.
            name_filter: Wildcard filter on variable name (e.g. '*JAVA*', '*PATH*'). Empty = all.
            scope: Machine (default), User, or Process.
        """
        scope_map = {"machine": "Machine", "user": "User", "process": "Process"}
        sc = scope_map.get(scope.strip().lower())
        if not sc:
            return {"error": "scope must be 'Machine', 'User', or 'Process'"}

        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.Name -like '" + safe_nf + "' } "

        cmd = (
            "[Environment]::GetEnvironmentVariables('" + sc + "').GetEnumerator() "
            "| Select-Object Name, Value "
            + name_where +
            "| Sort-Object Name "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_environment_variables")

    @mcp.tool()
    def get_scheduled_tasks(
        session_id: str,
        name_filter: str = "",
        include_disabled: bool = False,
    ) -> dict[str, Any]:
        """List Windows scheduled tasks showing name, state, last run time, last result, and next run time. Essential for understanding what automated jobs run on this server (backups, cleanup, AQS jobs, batch processes). Returns tabular text.

        Args:
            session_id: Session ID from connect.
            name_filter: Wildcard filter on task name (e.g. '*backup*', '*AQS*'). Empty = all non-Microsoft tasks.
            include_disabled: Include disabled tasks (default False — only shows Ready/Running).
        """
        where_parts: list[str] = []

        if not include_disabled:
            where_parts.append("$_.State -ne 'Disabled'")

        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            where_parts.append("$_.TaskName -like '" + safe_nf + "'")
        else:
            where_parts.append("$_.TaskPath -notlike '\\Microsoft\\*'")

        where = "| Where-Object { " + " -and ".join(where_parts) + " } "

        cmd = (
            "Get-ScheduledTask -ErrorAction SilentlyContinue "
            + where +
            "| ForEach-Object { "
            "$info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue; "
            "[PSCustomObject]@{"
            "Name=$_.TaskName; "
            "State=[string]$_.State; "
            "LastRun=if($info.LastRunTime -and $info.LastRunTime.Year -gt 1999)"
            "{$info.LastRunTime.ToString('yyyy-MM-dd HH:mm')}else{'Never'}; "
            "LastResult=if($info){$info.LastTaskResult}else{'N/A'}; "
            "NextRun=if($info.NextRunTime -and $info.NextRunTime.Year -gt 1999)"
            "{$info.NextRunTime.ToString('yyyy-MM-dd HH:mm')}else{'None'}"
            "}} "
            "| Sort-Object Name "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_scheduled_tasks")

    @mcp.tool()
    def get_local_users(session_id: str) -> dict[str, Any]:
        """List local user accounts on the server showing name, enabled status, last logon, and description. Use to check for rogue accounts, locked-out service accounts, or disabled accounts. Returns tabular text.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "Get-LocalUser -ErrorAction Stop "
            "| Select-Object Name, Enabled, "
            "@{N='LastLogon';E={if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm')}else{'Never'}}}, "
            "@{N='PasswordExpires';E={if($_.PasswordExpires){$_.PasswordExpires.ToString('yyyy-MM-dd')}else{'Never'}}}, "
            "Description "
            "| Sort-Object Name "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_local_users")

    @mcp.tool()
    def get_user_groups(
        session_id: str,
        username: str = "",
    ) -> dict[str, Any]:
        """Show local group memberships. With no username, lists all local groups and their members. With a username, shows which local groups that user belongs to (matches both local and domain\\user formats). For full AD domain group membership of the current WinRM session, use get_security_context instead — it reads groups directly from the authentication token without needing DC access. Returns tabular text.

        Args:
            session_id: Session ID from connect.
            username: User to look up (e.g. 'Administrator', 'DOMAIN\\\\svc-account'). Empty = list all local groups with members.
        """
        if username.strip():
            safe_user = _ps_escape(username.strip())
            cmd = (
                "$u = '" + safe_user + "'; "
                "Write-Output '=== Local Group Memberships ==='; "
                "$found = @(); "
                "Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object { "
                "$members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue; "
                "$match = $members | Where-Object { $_.Name -eq $u -or $_.Name -like \"*\\$u\" }; "
                "if ($match) { $found += [PSCustomObject]@{Group=$_.Name; Description=$_.Description} } "
                "}; "
                "if ($found) { $found | Format-Table -AutoSize -Wrap | Out-String -Width 300 } "
                "else { Write-Output '  (not a member of any local groups)' }; "
                "Write-Output ''; "
                "Write-Output 'TIP: For full AD group membership of the current session, use get_security_context.'"
            )
        else:
            cmd = (
                "Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object { "
                "$g = $_.Name; "
                "$members = (Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue "
                "| Select-Object -ExpandProperty Name) -join ', '; "
                "[PSCustomObject]@{Group=$g; Members=if($members){$members}else{'(empty)'}} "
                "} | Format-Table -AutoSize -Wrap | Out-String -Width 300"
            )
        return sm.run_ps(session_id, cmd, tool_name="get_user_groups")

    @mcp.tool()
    def get_security_context(session_id: str) -> dict[str, Any]:
        """Show the current WinRM session's security context — equivalent to 'whoami /all'. Returns the identity running commands, group memberships (including AD domain groups), privileges, and integrity level. Essential for diagnosing 'access denied' errors and understanding what the service account can actually do.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "$wi = [Security.Principal.WindowsIdentity]::GetCurrent(); "
            "$wp = New-Object Security.Principal.WindowsPrincipal($wi); "
            "$elevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
            "$groups = $wi.Groups | ForEach-Object { "
            "try { $_.Translate([Security.Principal.NTAccount]).Value } "
            "catch { $_.Value } "
            "} | Sort-Object; "
            "$privs = whoami /priv /fo csv 2>$null | ConvertFrom-Csv "
            "| Select-Object @{N='Privilege';E={$_.'Privilege Name'}}, "
            "@{N='Enabled';E={$_.State -eq 'Enabled'}}; "
            "[PSCustomObject]@{"
            "Identity=$wi.Name; "
            "SID=$wi.User.Value; "
            "AuthType=$wi.AuthenticationType; "
            "IsElevated=$elevated; "
            "IntegrityLevel=if($elevated){'High'}else{'Medium'}; "
            "Groups=$groups; "
            "GroupCount=$groups.Count; "
            "Privileges=@($privs)"
            "} | ConvertTo-Json -Compress -Depth 3"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_security_context")

    @mcp.tool()
    def get_permissions(
        session_id: str,
        path: str,
    ) -> dict[str, Any]:
        """Get the access control list (ACL) for a file or folder. Shows each permission entry: who has access, what type (Allow/Deny), and what rights (FullControl, Read, Write, Modify, etc.). Essential for troubleshooting "access denied" errors. Returns tabular text.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to the file or folder to check.
        """
        safe = _ps_escape(path)
        cmd = (
            "$acl = Get-Acl -LiteralPath '" + safe + "' -ErrorAction Stop; "
            "Write-Output (\"Owner: \" + $acl.Owner); "
            "Write-Output ''; "
            "$acl.Access "
            "| Select-Object "
            "@{N='Identity';E={$_.IdentityReference}}, "
            "AccessControlType, "
            "@{N='Rights';E={$_.FileSystemRights}}, "
            "@{N='Inherited';E={$_.IsInherited}} "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_permissions")

    # ==================================================================
    # Network, DNS, software, file comparison — read-only
    # ==================================================================

    @mcp.tool()
    def get_tcp_connections(
        session_id: str,
        state_filter: str = "Established",
        port_filter: int = 0,
    ) -> dict[str, Any]:
        """List active TCP connections showing local/remote addresses, ports, state, and owning process. Like 'ss -tnp' or 'netstat -an' on Linux. Use to check database connections, find connection leaks, or see what's talking to what. Returns tabular text.

        Args:
            session_id: Session ID from connect.
            state_filter: Filter by state: Established (default), Listen, TimeWait, CloseWait, All.
            port_filter: Only show connections involving this port (0 = all ports).
        """
        state_map = {
            "established": "Established", "listen": "Listen",
            "timewait": "TimeWait", "closewait": "CloseWait",
            "finwait1": "FinWait1", "finwait2": "FinWait2",
            "synreceived": "SynReceived", "bound": "Bound",
        }

        where_parts: list[str] = []
        sf = state_filter.strip().lower()
        if sf != "all":
            ps_state = state_map.get(sf, "Established")
            where_parts.append("$_.State -eq '" + ps_state + "'")

        if port_filter > 0:
            where_parts.append(
                "($_.LocalPort -eq " + str(port_filter) +
                " -or $_.RemotePort -eq " + str(port_filter) + ")"
            )

        where = ""
        if where_parts:
            where = "| Where-Object { " + " -and ".join(where_parts) + " } "

        cmd = (
            "Get-NetTCPConnection -ErrorAction SilentlyContinue "
            + where +
            "| Select-Object "
            "@{N='Local';E={\"$($_.LocalAddress):$($_.LocalPort)\"}}, "
            "@{N='Remote';E={\"$($_.RemoteAddress):$($_.RemotePort)\"}}, "
            "State, "
            "@{N='PID';E={$_.OwningProcess}}, "
            "@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} "
            "| Sort-Object Remote "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_tcp_connections")

    @mcp.tool()
    def get_dns_cache(
        session_id: str,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """Read the local DNS client cache. Shows cached DNS lookups with record name, type, TTL, and resolved data. Use to diagnose "it resolves wrong from this server" or stale DNS after a migration. Returns tabular text.

        Args:
            session_id: Session ID from connect.
            name_filter: Wildcard filter on record name (e.g. '*sql*', '*myapp*'). Empty = all cached entries.
        """
        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.Entry -like '" + safe_nf + "' } "

        cmd = (
            "Get-DnsClientCache -ErrorAction SilentlyContinue "
            + name_where +
            "| Select-Object Entry, "
            "@{N='Type';E={$_.Type}}, "
            "@{N='TTL_s';E={$_.TimeToLive}}, "
            "@{N='Data';E={$_.Data}} "
            "| Sort-Object Entry "
            "| Select-Object -First 100 "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_dns_cache")

    @mcp.tool()
    def get_installed_software(
        session_id: str,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List installed software with name, version, publisher, and install date. Reads from both 64-bit and 32-bit uninstall registry keys. Use to check Java, .NET, SQL, or any application version. Returns tabular text.

        Args:
            session_id: Session ID from connect.
            name_filter: Wildcard filter on software name (e.g. '*java*', '*sql*', '*.NET*'). Empty = all.
        """
        name_where = ""
        if name_filter.strip():
            safe_nf = _ps_escape(name_filter.strip())
            name_where = "| Where-Object { $_.DisplayName -like '" + safe_nf + "' } "

        cmd = (
            "$paths = @("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
            "$paths | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } "
            "| Where-Object { $_.DisplayName } "
            + name_where +
            "| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate "
            "| Sort-Object DisplayName -Unique "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="get_installed_software")

    @mcp.tool()
    def compare_files(
        session_id: str,
        path_a: str,
        path_b: str,
        max_diffs: int = 50,
    ) -> dict[str, Any]:
        """Compare two files and show the differences line by line (like diff). Shows line number and which file each differing line belongs to (=> file A, <= file B). Use to compare configs between environments. Returns text output.

        Args:
            session_id: Session ID from connect.
            path_a: Absolute path to the first file.
            path_b: Absolute path to the second file.
            max_diffs: Maximum number of differing lines to show (default 50).
        """
        safe_a = _ps_escape(path_a)
        safe_b = _ps_escape(path_b)
        cap = max(1, min(max_diffs, 200))
        cmd = (
            "$a = Get-Content -LiteralPath '" + safe_a + "' -ErrorAction Stop; "
            "$b = Get-Content -LiteralPath '" + safe_b + "' -ErrorAction Stop; "
            "Write-Output (\"File A: " + safe_a + " ($($a.Count) lines)\"); "
            "Write-Output (\"File B: " + safe_b + " ($($b.Count) lines)\"); "
            "Write-Output ''; "
            "$diff = Compare-Object -ReferenceObject $a -DifferenceObject $b -ErrorAction Stop; "
            "if (-not $diff) { Write-Output 'Files are identical.' } "
            "else { "
            "Write-Output (\"$($diff.Count) differences found:\"); "
            "Write-Output ''; "
            "$diff | Select-Object -First " + str(cap) + " "
            "@{N='Line';E={$_.InputObject}}, "
            "@{N='Source';E={if($_.SideIndicator -eq '=>'){'B (only)'}else{'A (only)'}}} "
            "| Format-Table -AutoSize -Wrap | Out-String -Width 300 }"
        )
        return sm.run_ps(session_id, cmd, tool_name="compare_files")

    # ==================================================================
    # DNS resolution — read-only
    # ==================================================================

    @mcp.tool()
    def resolve_dns_name(
        session_id: str,
        name: str,
        record_type: str = "A",
        dns_server: str = "",
    ) -> dict[str, Any]:
        """Resolve a DNS name from the remote server's perspective. Shows the full resolution chain including CNAMEs. Use to verify DNS propagation, check what IP a hostname resolves to, or compare resolution between servers. Returns tabular text.

        Args:
            session_id: Session ID from connect.
            name: Hostname or FQDN to resolve (e.g. 'db-server-01', 'db.example.com').
            record_type: DNS record type: A (default), AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT.
            dns_server: Specific DNS server to query (optional). Empty = use system default DNS.
        """
        valid_types = {"a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt"}
        rt = record_type.strip().upper()
        if rt.lower() not in valid_types:
            return {"error": f"Invalid record_type '{record_type}'. Valid: {', '.join(sorted(t.upper() for t in valid_types))}"}

        safe_name = _ps_escape(name)
        server_arg = ""
        if dns_server.strip():
            safe_dns = _ps_escape(dns_server.strip())
            server_arg = " -Server '" + safe_dns + "'"

        cmd = (
            "Resolve-DnsName -Name '" + safe_name + "' "
            "-Type " + rt + server_arg + " -ErrorAction Stop "
            "| Select-Object Name, Type, TTL, "
            "@{N='Data';E={"
            "if($_.IPAddress){$_.IPAddress}"
            "elseif($_.NameHost){$_.NameHost}"
            "elseif($_.NameExchange){\"$($_.NameExchange) (pri:$($_.Preference))\"}"
            "elseif($_.NameTarget){\"$($_.NameTarget):$($_.Port)\"}"
            "elseif($_.Strings){$_.Strings -join ' '}"
            "elseif($_.PrimaryServer){$_.PrimaryServer}"
            "else{'N/A'}"
            "}} "
            "| Format-Table -AutoSize | Out-String -Width 300"
        )
        return sm.run_ps(session_id, cmd, tool_name="resolve_dns_name")

    # ==================================================================
    # Write operations (all require user confirmation via elicitation)
    # ==================================================================

    async def _confirm(ctx: Context, action: str, details: str) -> bool:
        """Prompt the user to confirm a destructive/modifying action."""
        try:
            result = await ctx.elicit(
                message=f"Confirm {action}?\n\n{details}",
                response_type=None,
            )
            return result.action == "accept"
        except Exception:
            logger.error("Elicitation unavailable — rejecting modification (client must support elicitation)")
            return False

    @mcp.tool()
    async def flush_dns(
        session_id: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Clear the local DNS client cache on the remote server. Forces all future DNS lookups to re-resolve from the DNS server. Harmless operation but prompts for confirmation. Use after a DNS migration, failover, or when stale DNS entries are suspected.

        Args:
            session_id: Session ID from connect.
        """
        confirmed = await _confirm(
            ctx, "FLUSH DNS CACHE",
            "This will clear all cached DNS entries on the remote server.\nAll future lookups will re-resolve from the DNS server.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Flush DNS cancelled by user"}

        cmd = (
            "$before = (Get-DnsClientCache -ErrorAction SilentlyContinue | Measure-Object).Count; "
            "Clear-DnsClientCache; "
            "$after = (Get-DnsClientCache -ErrorAction SilentlyContinue | Measure-Object).Count; "
            "Write-Output \"DNS cache flushed. Entries before: $before, after: $after\""
        )
        return sm.run_ps(session_id, cmd, tool_name="flush_dns")

    @mcp.tool()
    async def invoke_http_request(
        session_id: str,
        url: str,
        ctx: Context,
        method: str = "GET",
        headers: str = "",
        body: str = "",
        timeout_sec: int = 15,
    ) -> dict[str, Any]:
        """Make an HTTP request FROM the remote Windows server. Tests connectivity and API health from the server's network perspective. Supports GET, HEAD, POST, PUT, DELETE. Shows status code, headers, and response body. Prompts for confirmation since it makes a network request from the remote host.

        Args:
            session_id: Session ID from connect.
            url: Full URL to request (e.g. 'http://localhost:8080/health', 'https://api.example.com/status').
            method: HTTP method: GET (default), HEAD, POST, PUT, DELETE.
            headers: Optional headers as 'Key:Value' pairs separated by '|' (e.g. 'Content-Type:application/json|Accept:text/plain').
            body: Optional request body for POST/PUT. Max 64KB.
            timeout_sec: Request timeout in seconds (default 15, max 60).
        """
        valid_methods = {"GET", "HEAD", "POST", "PUT", "DELETE"}
        m = method.strip().upper()
        if m not in valid_methods:
            return {"error": f"Invalid method '{method}'. Valid: {', '.join(sorted(valid_methods))}"}
        if len(body) > 65536:
            return {"error": "Body exceeds 64KB limit"}
        timeout = max(1, min(timeout_sec, 60))

        details = f"Method: {m}\nURL: {url}"
        if headers:
            details += f"\nHeaders: {headers}"
        if body:
            preview = body[:200] + ("..." if len(body) > 200 else "")
            details += f"\nBody: {preview}"
        details += f"\nTimeout: {timeout}s"

        confirmed = await _confirm(
            ctx, "HTTP REQUEST (from remote server)",
            details,
        )
        if not confirmed:
            return {"status": "cancelled", "message": "HTTP request cancelled by user"}

        safe_url = _ps_escape(url)

        header_block = ""
        if headers.strip():
            pairs: list[str] = []
            for pair in headers.split("|"):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    pairs.append(
                        "'" + _ps_escape(k.strip()) + "'='"
                        + _ps_escape(v.strip()) + "'"
                    )
            if pairs:
                header_block = "$hdrs = @{" + "; ".join(pairs) + "}; "

        body_block = ""
        if body and m in ("POST", "PUT"):
            b64_body = base64.b64encode(body.encode("utf-8")).decode("ascii")
            body_block = (
                "$bodyBytes = [Convert]::FromBase64String('" + b64_body + "'); "
                "$bodyStr = [System.Text.Encoding]::UTF8.GetString($bodyBytes); "
            )

        hdr_arg = " -Headers $hdrs" if header_block else ""
        body_arg = " -Body $bodyStr" if body_block else ""
        content_type_arg = ""
        if body and m in ("POST", "PUT") and "content-type" not in headers.lower():
            content_type_arg = " -ContentType 'application/json'"

        cmd = (
            header_block + body_block +
            "$ProgressPreference = 'SilentlyContinue'; "
            "try { "
            "$r = Invoke-WebRequest -Uri '" + safe_url + "' "
            "-Method " + m + " "
            "-TimeoutSec " + str(timeout) +
            " -UseBasicParsing"
            + hdr_arg + body_arg + content_type_arg +
            " -ErrorAction Stop; "
            "[PSCustomObject]@{"
            "StatusCode=$r.StatusCode; "
            "StatusDescription=$r.StatusDescription; "
            "ContentLength=$r.RawContentLength; "
            "Headers=($r.Headers | ConvertTo-Json -Compress); "
            "Body=$r.Content.Substring(0,[Math]::Min($r.Content.Length,8000))"
            "} | ConvertTo-Json -Compress"
            " } catch { "
            "$e = $_.Exception; "
            "if ($e.Response) { "
            "[PSCustomObject]@{"
            "StatusCode=[int]$e.Response.StatusCode; "
            "StatusDescription=$e.Response.ReasonPhrase; "
            "Error=$e.Message.Substring(0,[Math]::Min($e.Message.Length,500))"
            "} | ConvertTo-Json -Compress"
            " } else { "
            "throw $e"
            " }}"
        )
        return sm.run_ps(session_id, cmd, tool_name="invoke_http_request")

    @mcp.tool()
    async def compress_archive(
        session_id: str,
        source_path: str,
        destination_zip: str,
        ctx: Context,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Compress a file or directory into a .zip archive. Prompts for confirmation. Use to archive logs, back up config directories, or bundle files for transfer. Shows the resulting archive size.

        Args:
            session_id: Session ID from connect.
            source_path: File or directory to compress (e.g. 'C:\\App\\config' or 'C:\\temp\\myfile.log').
            destination_zip: Path for the output .zip file (e.g. 'C:\\backup\\configs.zip').
            overwrite: Allow overwriting an existing zip file (default False).
        """
        safe_src = _ps_escape(source_path)
        safe_dst = _ps_escape(destination_zip)

        src_info_cmd = (
            "$s = Get-Item -LiteralPath '" + safe_src + "' -ErrorAction Stop; "
            "if ($s.PSIsContainer) { "
            "$items = (Get-ChildItem -LiteralPath '" + safe_src + "' -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count; "
            "$size = (Get-ChildItem -LiteralPath '" + safe_src + "' -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; "
            "Write-Output \"Directory: $($s.FullName) ($items files, $([math]::Round($size/1MB,1)) MB)\" "
            "} else { "
            "Write-Output \"File: $($s.FullName) ($([math]::Round($s.Length/1MB,2)) MB)\" }"
        )
        src_info = sm.run_ps(session_id, src_info_cmd, tool_name="compress_archive")
        if "error" in src_info:
            return src_info
        src_desc = src_info.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "COMPRESS to ZIP",
            f"Source: {src_desc}\nDestination: {destination_zip}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Compress cancelled by user"}

        overwrite_check = ""
        if not overwrite:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ throw 'Destination zip already exists. Set overwrite=True to replace.' }; "
            )
        else:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ Remove-Item -LiteralPath '" + safe_dst + "' -Force }; "
            )

        cmd = (
            overwrite_check +
            "Compress-Archive -Path '" + safe_src + "' "
            "-DestinationPath '" + safe_dst + "' -ErrorAction Stop; "
            "Get-Item -LiteralPath '" + safe_dst + "' "
            "| Select-Object FullName, "
            "@{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}}, "
            "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="compress_archive")

    @mcp.tool()
    async def expand_archive(
        session_id: str,
        zip_path: str,
        destination_dir: str,
        ctx: Context,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Extract a .zip archive to a directory. Prompts for confirmation showing archive size and entry count. Use to unpack backups, deploy packages, or restore config archives.

        Args:
            session_id: Session ID from connect.
            zip_path: Path to the .zip file to extract.
            destination_dir: Directory to extract into (created if it doesn't exist).
            overwrite: Overwrite existing files in destination (default False).
        """
        safe_zip = _ps_escape(zip_path)
        safe_dst = _ps_escape(destination_dir)

        zip_info_cmd = (
            "$z = Get-Item -LiteralPath '" + safe_zip + "' -ErrorAction Stop; "
            "Add-Type -AssemblyName System.IO.Compression.FileSystem; "
            "$archive = [IO.Compression.ZipFile]::OpenRead($z.FullName); "
            "$count = $archive.Entries.Count; $archive.Dispose(); "
            "Write-Output \"$($z.FullName) ($([math]::Round($z.Length/1MB,2)) MB, $count entries)\""
        )
        zip_info = sm.run_ps(session_id, zip_info_cmd, tool_name="expand_archive")
        if "error" in zip_info:
            return zip_info
        zip_desc = zip_info.get("stdout", "").strip()

        dst_exists = ""
        exists_check = sm.run_ps(  # noqa: tool_name not needed for this quick check
            session_id,
            "if (Test-Path -LiteralPath '" + safe_dst + "') { Write-Output 'EXISTS' } else { Write-Output 'NEW' }"
        )
        dst_status = exists_check.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "EXTRACT ZIP",
            f"Archive: {zip_desc}\nExtract to: {destination_dir} ({dst_status})\nOverwrite files: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Extract cancelled by user"}

        force_arg = " -Force" if overwrite else ""
        cmd = (
            "Expand-Archive -LiteralPath '" + safe_zip + "' "
            "-DestinationPath '" + safe_dst + "'"
            + force_arg + " -ErrorAction Stop; "
            "$items = Get-ChildItem -LiteralPath '" + safe_dst + "' -Recurse -File -ErrorAction SilentlyContinue; "
            "[PSCustomObject]@{"
            "ExtractedTo='" + safe_dst + "'; "
            "FileCount=$items.Count; "
            "TotalSizeMB=[math]::Round(($items | Measure-Object -Property Length -Sum).Sum/1MB,2)"
            "} | ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="expand_archive")

    @mcp.tool()
    async def copy_file(
        session_id: str,
        source: str,
        destination: str,
        ctx: Context,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Copy a file to a new location. Prompts the user for confirmation. Does NOT overwrite by default — set overwrite=True to replace an existing destination file.

        Args:
            session_id: Session ID from connect.
            source: Absolute path of the file to copy.
            destination: Absolute path for the copy.
            overwrite: Allow overwriting the destination if it exists (default False).
        """
        confirmed = await _confirm(
            ctx, "COPY FILE",
            f"From: {source}\nTo:   {destination}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Copy cancelled by user"}

        safe_src = _ps_escape(source)
        safe_dst = _ps_escape(destination)

        overwrite_check = ""
        if not overwrite:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ throw 'Destination already exists. Set overwrite=True to replace.' }; "
            )

        cmd = (
            overwrite_check +
            "Copy-Item -LiteralPath '" + safe_src + "' "
            "-Destination '" + safe_dst + "' -Force -ErrorAction Stop; "
            "Get-Item -LiteralPath '" + safe_dst + "' "
            "| Select-Object FullName, Length, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="copy_file")

    @mcp.tool()
    async def rename_file(
        session_id: str,
        path: str,
        new_name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Rename a file or directory (stays in the same folder). Prompts the user for confirmation. Use move_file to move across directories.

        Args:
            session_id: Session ID from connect.
            path: Absolute path of the file or directory to rename.
            new_name: New filename only (not a full path, e.g. 'config_v2.xml').
        """
        if "/" in new_name or "\\" in new_name:
            return {"error": "new_name must be a filename only, not a path. Use move_file to move across directories."}

        confirmed = await _confirm(
            ctx, "RENAME FILE",
            f"Path: {path}\nNew name: {new_name}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Rename cancelled by user"}

        safe_path = _ps_escape(path)
        safe_name = _ps_escape(new_name)
        cmd = (
            "Rename-Item -LiteralPath '" + safe_path + "' "
            "-NewName '" + safe_name + "' -ErrorAction Stop; "
            "$parent = Split-Path -Parent '" + safe_path + "'; "
            "Get-Item -LiteralPath (Join-Path $parent '" + safe_name + "') "
            "| Select-Object FullName, Length, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="rename_file")

    @mcp.tool()
    async def move_file(
        session_id: str,
        source: str,
        destination: str,
        ctx: Context,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Move a file to a different location. Prompts the user for confirmation. Does NOT overwrite by default. Use rename_file if staying in the same directory.

        Args:
            session_id: Session ID from connect.
            source: Absolute path of the file to move.
            destination: Absolute destination path (full path including filename).
            overwrite: Allow overwriting the destination if it exists (default False).
        """
        confirmed = await _confirm(
            ctx, "MOVE FILE",
            f"From: {source}\nTo:   {destination}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Move cancelled by user"}

        safe_src = _ps_escape(source)
        safe_dst = _ps_escape(destination)

        overwrite_check = ""
        if not overwrite:
            overwrite_check = (
                "if (Test-Path -LiteralPath '" + safe_dst + "') "
                "{ throw 'Destination already exists. Set overwrite=True to replace.' }; "
            )

        cmd = (
            overwrite_check +
            "Move-Item -LiteralPath '" + safe_src + "' "
            "-Destination '" + safe_dst + "' -Force -ErrorAction Stop; "
            "Get-Item -LiteralPath '" + safe_dst + "' "
            "| Select-Object FullName, Length, "
            "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="move_file")

    @mcp.tool()
    async def create_directory(
        session_id: str,
        path: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Create a directory (and any missing parent directories). If the directory already exists, returns its info without error. Prompts for confirmation. Use this before write_file when the target folder might not exist.

        Args:
            session_id: Session ID from connect.
            path: Absolute path of the directory to create (e.g. 'C:\\backup\\2026-04-26').
        """
        safe = _ps_escape(path)

        exists_cmd = (
            "if (Test-Path -LiteralPath '" + safe + "') { "
            "$d = Get-Item -LiteralPath '" + safe + "' -Force; "
            "if (-not $d.PSIsContainer) { Write-Output 'EXISTS_AS_FILE' } "
            "else { Write-Output 'EXISTS_AS_DIR' } "
            "} else { Write-Output 'NOT_EXISTS' }"
        )
        check = sm.run_ps(session_id, exists_cmd, tool_name="create_directory")
        if "error" in check or check.get("status_code", 0) != 0:
            return {"error": check.get("stderr") or check.get("error") or "Pre-check failed", **check}
        state = check.get("stdout", "").strip()

        if state == "EXISTS_AS_FILE":
            return {"error": f"Path already exists as a file, not a directory: {path}"}
        if state == "EXISTS_AS_DIR":
            info_cmd = (
                "Get-Item -LiteralPath '" + safe + "' -Force "
                "| Select-Object FullName, "
                "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}}, "
                "@{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
                "| ConvertTo-Json -Compress"
            )
            info = sm.run_ps(session_id, info_cmd, tool_name="create_directory")
            return {
                "status": "already_exists",
                "message": f"Directory already exists: {path}",
                "info": info.get("stdout", "").strip(),
            }

        confirmed = await _confirm(
            ctx, "CREATE DIRECTORY",
            f"Path: {path}\n\nThis will create the directory and any missing parent directories.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Create directory cancelled by user"}

        cmd = (
            "New-Item -Path '" + safe + "' -ItemType Directory -Force -ErrorAction Stop "
            "| Select-Object FullName, "
            "@{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}} "
            "| ConvertTo-Json -Compress"
        )
        return sm.run_ps(session_id, cmd, tool_name="create_directory")

    @mcp.tool()
    async def delete_file(
        session_id: str,
        path: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Delete a single file. Shows file metadata (name, size, modified time) in the confirmation prompt so you can verify the correct file. Refuses to delete directories — use delete_directory for that.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to the file to delete.
        """
        safe = _ps_escape(path)

        pre_cmd = (
            "$item = Get-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop; "
            "if ($item.PSIsContainer) { throw 'Path is a directory — use delete_directory instead' }; "
            "[PSCustomObject]@{"
            "FullName=$item.FullName; "
            "SizeBytes=$item.Length; "
            "SizeKB=[math]::Round($item.Length/1KB,2); "
            "SizeMB=[math]::Round($item.Length/1MB,2); "
            "Modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); "
            "Attributes=[string]$item.Attributes"
            "} | ConvertTo-Json -Compress"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="delete_file")
        if "error" in pre or pre.get("status_code", 0) != 0:
            return {"error": pre.get("stderr") or pre.get("error") or "Pre-check failed", **pre}
        file_desc = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "DELETE FILE",
            f"File details:\n{file_desc}\n\nThis will permanently delete the file. This cannot be undone.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Delete file cancelled by user"}

        del_cmd = (
            "Remove-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop; "
            "if (Test-Path -LiteralPath '" + safe + "') "
            "{ Write-Output 'WARNING: file still exists after deletion attempt' } "
            "else { Write-Output 'File deleted successfully' }"
        )
        post = sm.run_ps(session_id, del_cmd, tool_name="delete_file")
        return {
            "deleted_file": file_desc,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
        }

    @mcp.tool()
    async def delete_directory(
        session_id: str,
        path: str,
        ctx: Context,
        max_items: int = 5000,
    ) -> dict[str, Any]:
        """Delete a directory and all its contents recursively. Before confirming, scans the directory to show total file count and size. Refuses to delete if the item count exceeds max_items (default 5000) as a safety brake — raise the cap explicitly if you are sure. Will NOT delete drive roots or well-known system directories.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to the directory to delete.
            max_items: Safety cap — refuse deletion if more than this many items exist (default 5000, max 50000). Set higher only after reviewing the scan output.
        """
        safe = _ps_escape(path)
        cap = max(1, min(max_items, 50000))

        protected = [
            "C:\\", "C:\\Windows", "C:\\Windows\\System32",
            "C:\\Program Files", "C:\\Program Files (x86)",
            "C:\\Users", "C:\\ProgramData",
            "D:\\", "E:\\",
        ]
        path_upper = path.strip().rstrip("\\").upper()
        for p in protected:
            if path_upper == p.upper():
                return {"error": f"Refusing to delete protected path: {path}"}

        pre_cmd = (
            "$item = Get-Item -LiteralPath '" + safe + "' -Force -ErrorAction Stop; "
            "if (-not $item.PSIsContainer) { throw 'Path is a file — use delete_file instead' }; "
            "$files = @(Get-ChildItem -LiteralPath '" + safe + "' -Recurse -File -Force "
            "-ErrorAction SilentlyContinue | Select-Object -First " + str(cap + 1) + "); "
            "$dirs = @(Get-ChildItem -LiteralPath '" + safe + "' -Recurse -Directory -Force "
            "-ErrorAction SilentlyContinue | Select-Object -First " + str(cap + 1) + "); "
            "$totalSize = ($files | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum; "
            "if (-not $totalSize) { $totalSize = 0 }; "
            "[PSCustomObject]@{"
            "FullName=$item.FullName; "
            "FileCount=$files.Count; "
            "DirCount=$dirs.Count; "
            "TotalItems=($files.Count + $dirs.Count); "
            "TotalSizeMB=[math]::Round($totalSize/1MB,2); "
            "TotalSizeGB=[math]::Round($totalSize/1GB,3); "
            "Created=$item.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'); "
            "Modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')"
            "} | ConvertTo-Json -Compress"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="delete_directory")
        if "error" in pre or pre.get("status_code", 0) != 0:
            return {"error": pre.get("stderr") or pre.get("error") or "Pre-check failed", **pre}
        dir_desc = pre.get("stdout", "").strip()

        import json
        try:
            scan = json.loads(dir_desc)
            total_items = scan.get("TotalItems", 0)
        except (json.JSONDecodeError, TypeError):
            total_items = 0

        if total_items > cap:
            return {
                "error": f"Directory contains {total_items}+ items — exceeds safety cap of {cap}. "
                f"Review the scan and set max_items higher if you are sure.",
                "scan": dir_desc,
            }

        confirmed = await _confirm(
            ctx, "DELETE DIRECTORY (recursive)",
            f"Directory scan:\n{dir_desc}\n\nThis will permanently delete the directory and ALL "
            f"its contents. This cannot be undone.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Delete directory cancelled by user"}

        del_cmd = (
            "Remove-Item -LiteralPath '" + safe + "' -Recurse -Force -ErrorAction Stop; "
            "if (Test-Path -LiteralPath '" + safe + "') "
            "{ Write-Output 'WARNING: directory still exists after deletion attempt' } "
            "else { Write-Output 'Directory deleted successfully' }"
        )
        post = sm.run_ps(session_id, del_cmd, tool_name="delete_directory")
        return {
            "deleted_directory": dir_desc,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
        }

    # ==================================================================
    # Service management (all require user confirmation via elicitation)
    # ==================================================================

    def _svc_state_cmd(name: str) -> str:
        """Build PS to capture current service state as JSON."""
        safe = _ps_escape(name)
        return (
            "Get-Service -Name '" + safe + "' -ErrorAction Stop "
            "| Select-Object Name, Status, StartType, "
            "@{N='PID';E={(Get-CimInstance Win32_Service -Filter \"Name='$($_.Name)'\").ProcessId}} "
            "| ConvertTo-Json -Compress"
        )

    @mcp.tool()
    async def restart_service(
        session_id: str,
        name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Restart a Windows service. Captures service state before and after the restart and prompts the user for confirmation showing current status and PID. Returns both pre and post state so you can verify the restart succeeded (new PID = process recycled).

        Args:
            session_id: Session ID from connect.
            name: Exact service name (e.g. 'JBossEAP8', 'W3SVC', 'MSSQLSERVER'). Not the display name.
        """
        pre = sm.run_ps(session_id, _svc_state_cmd(name), tool_name="restart_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "RESTART SERVICE",
            f"Service: {name}\nCurrent state: {pre_stdout}\n\nThis will briefly stop and restart the service.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Restart cancelled by user"}

        safe = _ps_escape(name)
        cmd = (
            "Restart-Service -Name '" + safe + "' -Force -ErrorAction Stop; "
            "Start-Sleep -Seconds 2; "
            + _svc_state_cmd(name)
        )
        post = sm.run_ps(session_id, cmd, tool_name="restart_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def stop_service(
        session_id: str,
        name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Stop a running Windows service. Captures service state before and after, prompts the user for confirmation. Use start_service to bring it back up.

        Args:
            session_id: Session ID from connect.
            name: Exact service name (e.g. 'JBossEAP8'). Not the display name.
        """
        pre = sm.run_ps(session_id, _svc_state_cmd(name), tool_name="stop_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "STOP SERVICE",
            f"Service: {name}\nCurrent state: {pre_stdout}\n\nThis will stop the service. It will NOT restart automatically.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Stop cancelled by user"}

        safe = _ps_escape(name)
        cmd = (
            "Stop-Service -Name '" + safe + "' -Force -ErrorAction Stop; "
            "Start-Sleep -Seconds 2; "
            + _svc_state_cmd(name)
        )
        post = sm.run_ps(session_id, cmd, tool_name="stop_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def start_service(
        session_id: str,
        name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Start a stopped Windows service. Captures service state before and after, prompts the user for confirmation.

        Args:
            session_id: Session ID from connect.
            name: Exact service name (e.g. 'JBossEAP8'). Not the display name.
        """
        pre = sm.run_ps(session_id, _svc_state_cmd(name), tool_name="start_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "START SERVICE",
            f"Service: {name}\nCurrent state: {pre_stdout}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Start cancelled by user"}

        safe = _ps_escape(name)
        cmd = (
            "Start-Service -Name '" + safe + "' -ErrorAction Stop; "
            "Start-Sleep -Seconds 2; "
            + _svc_state_cmd(name)
        )
        post = sm.run_ps(session_id, cmd, tool_name="start_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    # ==================================================================
    # Process management (requires user confirmation via elicitation)
    # ==================================================================

    @mcp.tool()
    async def kill_process(
        session_id: str,
        pid: int,
        ctx: Context,
    ) -> dict[str, Any]:
        """Kill a process by PID. Captures process details (name, CPU, memory, start time) before killing and shows them in the confirmation prompt. Requires PID — use list_processes first to find the right one. The process is force-terminated immediately.

        Args:
            session_id: Session ID from connect.
            pid: Process ID to kill. Use list_processes to find the correct PID.
        """
        pre_cmd = (
            "Get-Process -Id " + str(pid) + " -ErrorAction Stop "
            "| Select-Object Id, ProcessName, "
            "@{N='CPU_s';E={[math]::Round($_.CPU,1)}}, "
            "@{N='Mem_MB';E={[math]::Round($_.WorkingSet64/1MB,1)}}, "
            "@{N='Started';E={if($_.StartTime){$_.StartTime.ToString('yyyy-MM-dd HH:mm')}else{'N/A'}}} "
            "| ConvertTo-Json -Compress"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="kill_process")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "KILL PROCESS",
            f"PID: {pid}\nProcess details: {pre_stdout}\n\nThis will FORCE TERMINATE the process immediately.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Kill cancelled by user"}

        kill_cmd = (
            "Stop-Process -Id " + str(pid) + " -Force -ErrorAction Stop; "
            "Write-Output 'Process " + str(pid) + " terminated'; "
            "Start-Sleep -Milliseconds 500; "
            "$still = Get-Process -Id " + str(pid) + " -ErrorAction SilentlyContinue; "
            "if ($still) { Write-Output 'WARNING: process still running' } "
            "else { Write-Output 'Confirmed: process no longer exists' }"
        )
        post = sm.run_ps(session_id, kill_cmd, tool_name="kill_process")
        return {
            "killed_process": pre_stdout,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    # ==================================================================
    # Registry — write (requires user confirmation via elicitation)
    # ==================================================================

    @mcp.tool()
    async def set_registry(
        session_id: str,
        key: str,
        value_name: str,
        value_data: str,
        value_type: str = "String",
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Set a registry value. Captures the current value before writing and shows old vs new in the confirmation prompt. Creates the value if it doesn't exist. Returns both pre and post state.

        Args:
            session_id: Session ID from connect.
            key: Registry path (e.g. 'HKLM:\\SOFTWARE\\MyApp'). Also accepts HKEY_LOCAL_MACHINE format.
            value_name: Name of the registry value to set.
            value_data: Data to write (as string — converted to the correct type by PowerShell).
            value_type: Registry value type: String (default), DWord, QWord, ExpandString, MultiString, Binary.
        """
        valid_types = {"string", "dword", "qword", "expandstring", "multistring", "binary"}
        vt = value_type.strip().lower()
        if vt not in valid_types:
            return {"error": f"Invalid value_type '{value_type}'. Valid: {', '.join(sorted(valid_types))}"}
        type_map = {
            "string": "String", "dword": "DWord", "qword": "QWord",
            "expandstring": "ExpandString", "multistring": "MultiString", "binary": "Binary",
        }
        ps_type = type_map[vt]

        k = key.strip()
        if k.upper().startswith("HKEY_"):
            k = "Registry::" + k
        safe_key = _ps_escape(k)
        safe_val = _ps_escape(value_name)
        safe_data = _ps_escape(value_data)

        pre_cmd = (
            "try { "
            "$v = Get-ItemProperty -Path '" + safe_key + "' "
            "-Name '" + safe_val + "' -ErrorAction Stop; "
            "Write-Output (\"CURRENT: \" + [string]$v.'" + safe_val + "') "
            "} catch { Write-Output 'CURRENT: (does not exist)' }"
        )
        pre = sm.run_ps(session_id, pre_cmd, tool_name="set_registry")
        if "error" in pre:
            return pre
        current_value = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "SET REGISTRY VALUE",
            f"Key: {k}\nValue: {value_name}\nType: {ps_type}\n\n{current_value}\nNEW:     {value_data}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Registry write cancelled by user"}

        set_cmd = (
            "if (-not (Test-Path -Path '" + safe_key + "')) { "
            "New-Item -Path '" + safe_key + "' -Force | Out-Null }; "
            "Set-ItemProperty -Path '" + safe_key + "' "
            "-Name '" + safe_val + "' "
            "-Value '" + safe_data + "' "
            "-Type " + ps_type + " -ErrorAction Stop; "
            "$v = Get-ItemProperty -Path '" + safe_key + "' "
            "-Name '" + safe_val + "' -ErrorAction Stop; "
            "[PSCustomObject]@{"
            "Key='" + safe_key + "'; "
            "Name='" + safe_val + "'; "
            "Value=[string]$v.'" + safe_val + "'; "
            "Type='" + ps_type + "'"
            "} | ConvertTo-Json -Compress"
        )
        post = sm.run_ps(session_id, set_cmd, tool_name="set_registry")
        return {
            "previous": current_value,
            "result": post.get("stdout", "").strip(),
            "status_code": post.get("status_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

