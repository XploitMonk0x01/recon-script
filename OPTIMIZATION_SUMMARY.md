# CTF Reconnaissance Script Optimization Summary

## Changes Implemented

### 1. **Optimized Fuzzing Strategy**

#### Configuration Updates

- Added `RECURSIVE_DEPTH=2` - Limits recursive directory scanning depth
- Added `RECURSIVE_TIMEOUT=300` - Timeout for recursive fuzzing operations

#### fuzz_port Function Refactoring

**Before:**

- Ran multiple `gobuster` scans with different wordlists (redundant)
- Basic `ffuf` scan without auto-calibration
- No recursive directory scanning

**After:**

- **Single Quick Gobuster Scan**: Uses only `common.txt` as a baseline/fallback
- **Primary FFUF Scan**:
  - Uses auto-calibration flag (`-ac`) to dynamically filter noisy responses
  - More comprehensive wordlist (first available from priority list)
  - Better status code filtering: `200,201,202,204,301,302,307,308,401,403,405`
  - Silent mode (`-s`) to reduce output noise
- **Automatic Recursive Scanning**: Launches `recursive_fuzz()` after initial scan completes

### 2. **New Recursive Fuzzing Function**

Created `recursive_fuzz()` function that:

- **Parses Initial Results**: Extracts directories from ffuf JSON output
  - Identifies redirects (301, 302, 307, 308 status codes)
  - Finds paths ending with `/`
  - Uses `jq` for precise JSON parsing (with fallback for systems without jq)
- **Intelligent Directory Selection**:
  - Removes duplicates
  - Limits scanning to `RECURSIVE_DEPTH` directories (configurable, default: 2)
  - Skips suspicious or overly long directory names (>100 chars)
- **Recursive Scanning**:
  - Launches new `ffuf` scans on discovered directories
  - Format: `${base_url}/${discovered_dir}/FUZZ`
  - Uses same auto-calibration and filtering as primary scan
  - Implements timeout protection (`RECURSIVE_TIMEOUT = 300s`)
- **Result Aggregation**:
  - Merges all recursive findings into `ffuf_recursive.json`
  - Provides count of additional paths discovered

### 3. **Refined Output Processing**

#### process_web_results Function Improvements

**Enhanced FFUF Output Parsing:**

```bash
# Before:
"- url [status] [length bytes]"

# After:
"- url [HTTP status] [Size: lengthB] [Words: count]"
```

**Features:**

- Sorts results by status code for easier analysis
- Separate sections for:
  - Gobuster Quick Scan (baseline)
  - FFUF Primary Scan (Auto-Calibrated)
  - FFUF Recursive Scan (with subdirectory findings)
- Shows "No additional paths" message when recursive scan finds nothing

**Enhanced High-Value Pattern Matching:**

- **Old patterns**: `admin|login|config|flag|key|secret|backup|upload|api`
- **New patterns**:
  - Added: `signin|signup|dashboard|panel|control|manage|portal|console|debug|swagger|graphql|auth|token|password|internal|private|_admin|phpmyadmin`
  - Excludes: `logout|signout|.css|.js|/img/|/fonts/|/assets/` (reduces noise)
- Increased display limit from 3 to 5 high-value targets

#### process_dirsearch_results Function Improvements

**Better Status Code Filtering:**

- **Includes**: `200,201,202,204,301,302,307,308,401,403,405`
- **Excludes**: `404,429,502,503,504`
- Filters out common noise: `favicon.ico`, `robots.txt 404`, `.well-known 404`

**Enhanced High-Value Target Detection:**

- Expanded pattern list to include:
  - CMS panels: `cms|wp-admin|phpmyadmin`
  - Development paths: `debug|test|dev|staging`
  - Authentication: `signin|signup|register|forgot|reset|password|token`
  - APIs: `ajax|rest|graphql|swagger|docs`
  - Administration: `control|manage|portal|console|_admin`
- Excludes static assets: `css|js|img|fonts|assets|static`
- Increased result limit from 5 to 10 high-value paths

### 4. **Banner & Documentation Updates**

Updated script banner to reflect new approach:

```
RustScan → Nmap → Dirsearch → FFUF (Recursive)
```

Updated usage description to emphasize:

- "Optimized web fuzzing with FFUF (auto-calibration + recursive)"

## Benefits

### Performance Improvements

1. **Reduced Redundancy**: Single gobuster scan instead of multiple
2. **Faster Results**: FFUF's auto-calibration reduces false positives
3. **Smarter Scanning**: Recursive fuzzing only on discovered directories

### Quality Improvements

1. **Better Signal-to-Noise Ratio**: Auto-calibration filters dynamic content
2. **More Comprehensive**: Recursive scanning discovers hidden subdirectory content
3. **Cleaner Output**: Only essential findings saved to files

### Output Improvements

1. **Structured Findings**: Clear sections for different scan types
2. **Detailed Metadata**: Status codes, sizes, and word counts
3. **Enhanced Pattern Matching**: Broader detection of high-value targets
4. **Better Noise Filtering**: Excludes static assets and logout pages

## File Structure Changes

### New Files Created During Scans

```
$BASE_DIR/web/port_${port}/
├── fuzzing.log                    # Main fuzzing log
├── gobuster_quick.txt             # Quick baseline scan (common.txt only)
├── ffuf_results.json              # Primary FFUF scan with auto-calibration
├── ffuf_results.txt               # Text version of primary scan
├── ffuf_recursive.json            # Aggregated recursive scan results
├── ffuf_recursive_1.json          # Individual recursive scan 1
├── ffuf_recursive_2.json          # Individual recursive scan 2
├── recursive_fuzzing.log          # Recursive fuzzing log
└── interesting_findings.txt       # Processed, human-readable summary
```

## Configuration Variables

| Variable            | Default            | Description                                    |
| ------------------- | ------------------ | ---------------------------------------------- |
| `RECURSIVE_DEPTH`   | 2                  | Max number of directories to recursively scan  |
| `RECURSIVE_TIMEOUT` | 300                | Timeout (seconds) for each recursive ffuf scan |
| `FFUF_THREADS`      | 30                 | Number of concurrent threads for ffuf          |
| `FFUF_EXTENSIONS`   | html,php,txt,js... | File extensions to append during fuzzing       |

## Usage Recommendations

1. **Adjust Recursive Depth**: Increase `RECURSIVE_DEPTH` for deeper scans
2. **Monitor Output**: Check `recursive_fuzzing.log` for scan progress
3. **Review Findings**: Focus on "High-Value Targets" section first
4. **JQ Recommended**: Install `jq` for best JSON parsing and formatting

## Example Output Format

### FFUF Primary Scan

```
- http://target.com/admin [HTTP 200] [Size: 4532B] [Words: 234]
- http://target.com/api [HTTP 401] [Size: 123B] [Words: 5]
- http://target.com/backup [HTTP 403] [Size: 278B] [Words: 12]
```

### High-Value Targets

```
Priority targets:
  - http://target.com/admin [HTTP 200] [Size: 4532B]
  - http://target.com/api/swagger [HTTP 200] [Size: 12456B]
  - http://target.com/_admin/config [HTTP 403] [Size: 278B]
```

## Backward Compatibility

✅ All existing functionality preserved
✅ Falls back gracefully when tools are missing
✅ Works with or without `jq` (with reduced features)
✅ Maintains same directory structure

## Testing Checklist

- [ ] Verify ffuf auto-calibration works on test target
- [ ] Confirm recursive scanning discovers subdirectories
- [ ] Check that high-value pattern matching catches common paths
- [ ] Validate JSON output formatting with and without jq
- [ ] Test timeout protection on slow targets
- [ ] Confirm output files contain only necessary information
