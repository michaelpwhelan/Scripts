# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES / APPLICATION STATE
# ═══════════════════════════════════════════════════════════════════════════════

$Script:State = @{
    FilePath        = $null
    OriginalPath    = $null
    Format          = "auto"
    Encoding        = "UTF-8"
    AllEntries      = [System.Collections.Generic.List[object]]::new()
    FilteredEntries = [System.Collections.Generic.List[object]]::new()
    BookmarkedSet   = [System.Collections.Generic.HashSet[int]]::new()
    TailMode        = $false
    TailByteOffset  = 0L
    TailTimer       = $null
    ActiveProfile   = $null
    ActiveTheme     = $Script:ThemeParam
    RecentFiles     = [System.Collections.Generic.List[string]]::new()
    ParseRunspace   = $null
    ParseHandle     = $null
    ResultQueue     = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    DrainTimer      = $null
    IsParsing       = $false
    SortColumn      = -1
    SortAscending   = $true
    EventIdLookup   = @{}
    NpsReasonLookup = @{}
    FilterProfiles  = @()
    CustomRegex     = $null
    ParsePowerShell = $null
    FontSize        = 9.0
    ColumnWidths    = @{}           # NEW: persisted column widths
    LoadedFiles     = [System.Collections.Generic.List[string]]::new()  # NEW: multi-file support
    IocSet          = $null         # NEW: IOC matching
    ParserState     = @{}           # NEW: parser-specific persistent state (e.g., IIS fields)
    RegexCache      = @{}           # NEW: compiled regex cache for filter engine
    CorrelationRules    = @()           # Loaded from data/correlation-rules.json
    PresetFilterProfiles = @()          # Loaded from data/filter-profiles.json
    QueryHistory        = [System.Collections.Generic.List[string]]::new()  # v5.0: SQL query history
    EntryIndex          = $null         # v5.0: search indexes from IndexEngine
    TriageRules         = @()           # v5.0: loaded triage rules
    ActiveConnectors    = @{}           # v5.0: live data connector states
    DashboardVisible    = $false        # v5.0: dashboard panel state
}

$Script:Parsers = [ordered]@{}
$Script:UI = @{}
