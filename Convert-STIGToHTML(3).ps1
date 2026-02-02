# Convert-STIGToHTML.ps1
# Converts multiple STIG Viewer 3 checklists (.cklb) into a summary HTML document
# Updated for STIG Viewer 3 JSON format

param(
    [Parameter(Mandatory=$false)]
    [string]$InputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "STIG_Summary_Report.html",
    
    [Parameter(Mandatory=$false)]
    [string]$ReportTitle = "",
    
    [Parameter(Mandatory=$false)]
    [string]$LogoBase64 = "",
    
    [Parameter(Mandatory=$false)]
    [string]$TopBannerText = "",
    
    [Parameter(Mandatory=$false)]
    [string]$TopBannerBgColor = "#3498db",
    
    [Parameter(Mandatory=$false)]
    [string]$TopBannerTextColor = "#ffffff",
    
    [Parameter(Mandatory=$false)]
    [string]$BottomBannerText = "",
    
    [Parameter(Mandatory=$false)]
    [string]$BottomBannerBgColor = "#3498db",
    
    [Parameter(Mandatory=$false)]
    [string]$BottomBannerTextColor = "#ffffff",
    
    [Parameter(Mandatory=$false)]
    [string]$ClassificationText = ""
)

# Function to parse .cklb file (JSON format)
function Parse-CKLBFile {
    param([string]$FilePath)
    
    try {
        # Read the JSON file directly
        $jsonContent = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        
        # Extract checklist info from JSON structure
        $checklistInfo = @{
            FileName = (Get-Item $FilePath).Name
            HostName = $jsonContent.target_data.host_name
            HostIP = $jsonContent.target_data.ip_address
            HostMAC = $jsonContent.target_data.mac_address
            FQDN = $jsonContent.target_data.fqdn
            Role = $jsonContent.target_data.role
            TechnologyArea = $jsonContent.target_data.technology_area
            Vulns = @()
        }
        
        # Process each STIG in the checklist
        foreach ($stig in $jsonContent.stigs) {
            # Store STIG-level information
            $stigInfo = @{
                STIGTitle = $stig.stig_name
                DisplayName = $stig.display_name
                STIGId = $stig.stig_id
                Version = $stig.release_info
                ReleaseInfo = $stig.release_info
            }
            
            # Add STIG info to checklist (use first STIG for main info)
            if (-not $checklistInfo.STIGTitle) {
                $checklistInfo.STIGTitle = $stigInfo.STIGTitle
                $checklistInfo.Version = $stigInfo.Version
                $checklistInfo.ReleaseInfo = $stigInfo.ReleaseInfo
            }
            
            # Extract vulnerability/rule data
            foreach ($rule in $stig.rules) {
                # Map status values from JSON format to display format
                $status = switch ($rule.status) {
                    "not_reviewed" { "Not_Reviewed" }
                    "not_applicable" { "Not_Applicable" }
                    "open" { "Open" }
                    "not_a_finding" { "NotAFinding" }
                    default { $rule.status }
                }
                
                # Check for severity overrides - handle multiple possible structures
                $severity = $rule.severity
                
                # Check for override at different possible paths
                if ($rule.overrides) {
                    if ($rule.overrides.severity) {
                        # Could be direct value or object with new_value
                        if ($rule.overrides.severity -is [string]) {
                            $severity = $rule.overrides.severity
                        }
                        elseif ($rule.overrides.severity.new_value) {
                            $severity = $rule.overrides.severity.new_value
                        }
                        elseif ($rule.overrides.severity.value) {
                            $severity = $rule.overrides.severity.value
                        }
                    }
                }
                
                # Normalize severity to lowercase to handle case variations
                if ($severity) {
                    $severity = $severity.ToString().ToLower().Trim()
                }
                
                $vulnData = @{
                    VulnID = $rule.group_id
                    RuleID = $rule.rule_id
                    Severity = $severity
                    GroupTitle = $rule.group_title
                    RuleTitle = $rule.rule_title
                    Status = $status
                    FindingDetails = $rule.finding_details
                    Comments = $rule.comments
                    Discussion = $rule.discussion
                    CheckContent = $rule.check_content
                    FixText = $rule.fix_text
                    RuleVersion = $rule.rule_version
                    CCIs = $rule.ccis -join ", "
                    LegacyIDs = $rule.legacy_ids -join ", "
                    STIGTitle = $stigInfo.STIGTitle
                }
                
                $checklistInfo.Vulns += $vulnData
            }
        }
        
        return $checklistInfo
    }
    catch {
        Write-Warning "Error parsing file $FilePath : $_"
        return $null
    }
}

# Get all .cklb files
Write-Host "Searching for .cklb files in: $InputPath"
$cklbFiles = Get-ChildItem -Path $InputPath -Filter "*.cklb" -Recurse

if ($cklbFiles.Count -eq 0) {
    Write-Host "No .cklb files found in $InputPath" -ForegroundColor Yellow
    exit
}

Write-Host "Found $($cklbFiles.Count) checklist(s). Processing..."

# Parse all checklists
$allChecklists = @()
foreach ($file in $cklbFiles) {
    Write-Host "Processing: $($file.Name)"
    $parsed = Parse-CKLBFile -FilePath $file.FullName
    if ($parsed) {
        $allChecklists += $parsed
    }
}

if ($allChecklists.Count -eq 0) {
    Write-Host "No checklists were successfully parsed." -ForegroundColor Red
    exit
}

# Generate HTML
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STIG Compliance Summary Report</title>
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-alt: #f8f9fa;
            --text-primary: #2c3e50;
            --text-secondary: #34495e;
            --text-light: #ecf0f1;
            --border-color: #ddd;
            --header-bg: #34495e;
            --header-hover: #2c3e50;
            --card-shadow: rgba(0,0,0,0.1);
            --finding-bg: #fff;
            --nested-finding-bg: #bdc3c7;
            --nested-finding-text: #2c3e50;
        }
        
        body.dark-mode {
            --bg-primary: #1e1e1e;
            --bg-secondary: #121212;
            --bg-alt: #2a2a2a;
            --text-primary: #e0e0e0;
            --text-secondary: #b0b0b0;
            --text-light: #e0e0e0;
            --border-color: #444;
            --header-bg: #2c3e50;
            --header-hover: #34495e;
            --card-shadow: rgba(0,0,0,0.5);
            --finding-bg: #2a2a2a;
            --nested-finding-bg: #3a3a3a;
            --nested-finding-text: #e0e0e0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: var(--bg-secondary);
            color: var(--text-primary);
            transition: background-color 0.3s, color 0.3s;
        }
        .banner {
            padding: 15px 20px;
            text-align: center;
            font-weight: bold;
            font-size: 18px;
        }
        .header-wrapper {
            background-color: var(--bg-secondary);
            padding: 20px 0;
        }
        .header-section {
            max-width: 1400px;
            margin: 0 auto;
            background-color: var(--bg-primary);
            padding: 20px 30px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            box-shadow: 0 2px 10px var(--card-shadow);
            position: relative;
        }
        .header-left {
            display: flex;
            align-items: center;
            gap: 20px;
            flex-grow: 1;
        }
        .logo-container {
            flex-shrink: 0;
        }
        .logo-container img {
            max-height: 100px;
            max-width: 200px;
        }
        .title-container {
            flex-grow: 1;
        }
        .report-title {
            color: var(--text-primary);
            font-size: 24px;
            font-weight: bold;
            margin: 0;
        }
        .dark-mode-toggle {
            position: absolute;
            top: 10px;
            right: 30px;
            cursor: pointer;
            background-color: var(--header-bg);
            color: var(--text-light);
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            font-size: 14px;
            transition: background-color 0.3s;
        }
        .dark-mode-toggle:hover {
            background-color: var(--header-hover);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: var(--bg-primary);
            padding: 30px;
            box-shadow: 0 2px 10px var(--card-shadow);
        }
        h1 {
            color: var(--text-primary);
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: var(--text-secondary);
            margin-top: 30px;
        }
        h3 {
            color: var(--text-light);
            margin-top: 20px;
        }
        h4 {
            color: var(--text-secondary);
            margin: 15px 0 10px 0;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px var(--card-shadow);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 14px;
            opacity: 0.9;
            color: white;
        }
        .summary-card .number {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        .checklist-section {
            margin: 15px 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        .checklist-header {
            background-color: var(--header-bg);
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .checklist-header:hover {
            background-color: var(--header-hover);
        }
        .checklist-header h3 {
            margin: 0 0 5px 0;
            color: var(--text-light);
        }
        .checklist-info {
            font-size: 14px;
            opacity: 0.9;
            margin-top: 10px;
        }
        .checklist-info span {
            display: inline-block;
            margin-right: 20px;
        }
        .checklist-body {
            padding: 20px;
            display: none;
            background-color: var(--bg-primary);
        }
        .checklist-body.active {
            display: block;
        }
        .collapse-icon {
            font-size: 20px;
            transition: transform 0.3s;
        }
        .collapse-icon.expanded {
            transform: rotate(180deg);
        }
        .stats-row {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            padding: 15px;
            background-color: var(--bg-alt);
            border-radius: 5px;
        }
        .stat-item {
            text-align: center;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
        }
        .stat-value.open { color: #e74c3c; }
        .stat-value.notafinding { color: #27ae60; }
        .stat-value.notreviewed { color: #f39c12; }
        .stat-value.notapplicable { color: #95a5a6; }
        .stats-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .stats-table th {
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        .stats-table td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
        }
        .stats-table tr:hover {
            background-color: var(--bg-alt);
        }
        .expandable-row {
            cursor: pointer;
        }
        .expandable-row:hover {
            background-color: #e8f4f8;
        }
        body.dark-mode .expandable-row:hover {
            background-color: #3a3a3a;
        }
        .expanded-content {
            display: none;
            background-color: var(--bg-alt);
            padding: 15px;
        }
        .expanded-content.active {
            display: block;
        }
        .rule-link {
            color: #3498db;
            text-decoration: none;
            display: block;
            padding: 5px 0;
            cursor: pointer;
        }
        .rule-link:hover {
            text-decoration: underline;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th {
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
        }
        tr:hover {
            background-color: var(--bg-alt);
        }
        .severity-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .severity-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .severity-low {
            color: #3498db;
            font-weight: bold;
        }
        .status-open {
            background-color: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-notafinding {
            background-color: #27ae60;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-notreviewed {
            background-color: #f39c12;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-notapplicable {
            background-color: #95a5a6;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .finding-card {
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            background-color: var(--finding-bg);
            scroll-margin-top: 20px;
            transition: background-color 0.3s ease;
        }
        .finding-card.highlight {
            background-color: #fff3cd;
            animation: highlightFade 2s ease-in-out;
        }
        @keyframes highlightFade {
            0% { background-color: #fff3cd; }
            100% { background-color: var(--finding-bg); }
        }
        .finding-card.severity-high {
            border-left: 5px solid #e74c3c;
        }
        .finding-card.severity-medium {
            border-left: 5px solid #f39c12;
        }
        .finding-card.severity-low {
            border-left: 5px solid #3498db;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .finding-title {
            font-weight: bold;
            font-size: 16px;
            color: var(--text-primary);
        }
        .finding-details {
            margin: 8px 0;
            font-size: 14px;
            color: var(--text-secondary);
        }
        .checklist-group {
            margin: 20px 0;
        }
        .checklist-group.alt-bg {
            background-color: var(--bg-alt);
            padding: 15px;
            border-radius: 5px;
        }
        .compliance-bar {
            display: flex;
            height: 40px;
            border-radius: 5px;
            overflow: hidden;
            margin: 20px 0;
            box-shadow: 0 2px 4px var(--card-shadow);
        }
        .bar-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 14px;
            transition: all 0.3s;
        }
        .bar-segment:hover {
            opacity: 0.8;
        }
        .bar-pass {
            background-color: #27ae60;
        }
        .bar-fail {
            background-color: #e74c3c;
        }
        .bar-notreviewed {
            background-color: #f39c12;
        }
        .bar-na {
            background-color: #95a5a6;
        }
        .timestamp {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background-color: #ecf0f1;
            border-radius: 5px;
            color: #7f8c8d;
            font-size: 14px;
        }
        body.dark-mode .timestamp {
            background-color: #2a2a2a;
            color: #b0b0b0;
        }
        .classification-footer {
            text-align: center;
            margin-top: 20px;
            padding: 15px;
            background-color: #e74c3c;
            color: white;
            font-weight: bold;
            font-size: 16px;
            border-radius: 5px;
        }
        
        /* Tab Styles */
        .tabs {
            display: flex;
            border-bottom: 2px solid #3498db;
            margin-top: 30px;
        }
        .tab-button {
            background-color: #ecf0f1;
            border: none;
            padding: 12px 24px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            color: #34495e;
            transition: all 0.3s;
            border-top-left-radius: 5px;
            border-top-right-radius: 5px;
            margin-right: 5px;
        }
        .tab-button:hover {
            background-color: #bdc3c7;
        }
        .tab-button.active {
            background-color: #3498db;
            color: white;
        }
        body.dark-mode .tab-button {
            background-color: #3a3a3a;
            color: #b0b0b0;
        }
        body.dark-mode .tab-button.active {
            background-color: #3498db;
            color: white;
        }
        .tab-content {
            display: none;
            padding: 20px 0;
        }
        .tab-content.active {
            display: block;
        }
        
        .collapsible-section {
            margin: 20px 0;
        }
        .collapsible-header {
            background-color: var(--header-bg);
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-radius: 5px;
        }
        .collapsible-header:hover {
            background-color: var(--header-hover);
        }
        .collapsible-header h2,
        .collapsible-header h3 {
            color: var(--text-light);
        }
        .collapsible-content {
            display: none;
            padding: 20px;
            border: 1px solid var(--border-color);
            border-top: none;
            border-radius: 0 0 5px 5px;
            background-color: var(--bg-primary);
        }
        .collapsible-content.active {
            display: block;
        }
        
        .nested-finding-header {
            background-color: var(--nested-finding-bg);
            color: var(--nested-finding-text);
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-radius: 5px;
        }
        .nested-finding-header:hover {
            opacity: 0.9;
        }
        .nested-finding-header div {
            color: var(--nested-finding-text);
        }
        
        .all-open-findings-section {
            margin: 15px 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        .all-open-findings-header {
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .all-open-findings-header h2 {
            margin: 0;
            color: var(--text-secondary);
        }
        .all-open-findings-body {
            padding: 20px;
            display: none;
            background-color: var(--bg-primary);
        }
        .all-open-findings-body.active {
            display: block;
        }
        
        .section-wrapper {
            margin: 15px 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        .section-header {
            color: white;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-header h2 {
            margin: 0;
            color: var(--text-secondary);
        }
        .section-body {
            padding: 20px;
            display: none;
            background-color: var(--bg-primary);
        }
        .section-body.active {
            display: block;
        }
        
        .host-list {
            margin: 10px 0;
            padding: 10px;
            background-color: var(--bg-alt);
            border-radius: 5px;
        }
        .host-item {
            padding: 5px 0;
            border-bottom: 1px solid var(--border-color);
        }
        .host-item:last-child {
            border-bottom: none;
        }
        
        @media print {
            body {
                background-color: white;
            }
            .container {
                box-shadow: none;
            }
            .tab-button {
                display: none;
            }
            .tab-content {
                display: block !important;
            }
            .collapsible-content {
                display: block !important;
            }
            .checklist-body {
                display: block !important;
            }
            .all-open-findings-body {
                display: block !important;
            }
            .section-body {
                display: block !important;
            }
            .banner {
                display: none;
            }
            .dark-mode-toggle {
                display: none;
            }
        }
    </style>
</head>
<body>
"@

# Add top banner if provided
if ($TopBannerText) {
    $html += "    <div class=`"banner`" style=`"background-color: $TopBannerBgColor; color: $TopBannerTextColor;`">$TopBannerText</div>`n"
}

# Add header section with logo and title
$html += "    <div class=`"header-wrapper`">`n"
$html += "        <div class=`"header-section`">`n"
$html += "            <button class=`"dark-mode-toggle`" onclick=`"toggleDarkMode()`">Toggle Dark Mode</button>`n"
$html += "            <div class=`"header-left`">`n"

if ($LogoBase64) {
    $html += @"
                <div class="logo-container">
                    <img src="$LogoBase64" alt="Logo">
                </div>
"@
}

if ($ReportTitle) {
    $html += @"
                <div class="title-container">
                    <div class="report-title">$ReportTitle</div>
                </div>
"@
}

$html += "            </div>`n"
$html += "        </div>`n"
$html += "    </div>`n"

$html += @"
    <div class="container">
        <h1>STIG Compliance Summary Report</h1>
"@

# Calculate overall statistics
$totalVulns = 0
$totalOpen = 0
$totalNotAFinding = 0
$totalNotReviewed = 0
$totalNA = 0
$totalHighOpen = 0
$totalMediumOpen = 0
$totalLowOpen = 0

foreach ($checklist in $allChecklists) {
    $totalVulns += $checklist.Vulns.Count
    $totalOpen += ($checklist.Vulns | Where-Object { $_.Status -eq "Open" }).Count
    $totalNotAFinding += ($checklist.Vulns | Where-Object { $_.Status -eq "NotAFinding" }).Count
    $totalNotReviewed += ($checklist.Vulns | Where-Object { $_.Status -eq "Not_Reviewed" }).Count
    $totalNA += ($checklist.Vulns | Where-Object { $_.Status -eq "Not_Applicable" }).Count
    
    $openVulns = $checklist.Vulns | Where-Object { $_.Status -eq "Open" }
    $totalHighOpen += ($openVulns | Where-Object { $_.Severity -eq "high" }).Count
    $totalMediumOpen += ($openVulns | Where-Object { $_.Severity -eq "medium" }).Count
    $totalLowOpen += ($openVulns | Where-Object { $_.Severity -eq "low" }).Count
}

# Calculate percentages for compliance bar
$passPercent = if ($totalVulns -gt 0) { [math]::Round(($totalNotAFinding / $totalVulns) * 100, 1) } else { 0 }
$failPercent = if ($totalVulns -gt 0) { [math]::Round(($totalOpen / $totalVulns) * 100, 1) } else { 0 }
$nrPercent = if ($totalVulns -gt 0) { [math]::Round(($totalNotReviewed / $totalVulns) * 100, 1) } else { 0 }
$naPercent = if ($totalVulns -gt 0) { [math]::Round(($totalNA / $totalVulns) * 100, 1) } else { 0 }

$html += @"
        <h2>Overall Compliance Summary</h2>
        <div style="display: flex; gap: 30px; align-items: flex-start; margin: 20px 0;">
            <div style="flex: 0 0 400px;">
                <svg id="complianceChart" viewBox="0 0 400 400" style="max-width: 400px; width: 100%;">
                    <!-- Pie chart will be generated here -->
                </svg>
                <div style="display: flex; flex-wrap: wrap; gap: 15px; margin-top: 20px; justify-content: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <div style="width: 20px; height: 20px; background-color: #27ae60; border-radius: 3px;"></div>
                        <span style="font-size: 12px; color: var(--text-primary);">Not a Finding ($totalNotAFinding)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <div style="width: 20px; height: 20px; background-color: #e74c3c; border-radius: 3px;"></div>
                        <span style="font-size: 12px; color: var(--text-primary);">Open ($totalOpen)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <div style="width: 20px; height: 20px; background-color: #f39c12; border-radius: 3px;"></div>
                        <span style="font-size: 12px; color: var(--text-primary);">Not Reviewed ($totalNotReviewed)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <div style="width: 20px; height: 20px; background-color: #95a5a6; border-radius: 3px;"></div>
                        <span style="font-size: 12px; color: var(--text-primary);">Not Applicable ($totalNA)</span>
                    </div>
                </div>
            </div>
            <div class="summary-grid" style="flex: 1; margin: 0;">
                <div class="summary-card" style="background: linear-gradient(135deg, #27ae60 0%, #229954 100%);">
                    <h3>NOT A FINDING</h3>
                    <div class="number">$totalNotAFinding</div>
                    <div>$passPercent% of total</div>
                </div>
                <div class="summary-card" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                    <h3>OPEN FINDINGS</h3>
                    <div class="number">$totalOpen</div>
                    <div>$failPercent% of total</div>
                </div>
                <div class="summary-card" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);">
                    <h3>NOT REVIEWED</h3>
                    <div class="number">$totalNotReviewed</div>
                    <div>$nrPercent% of total</div>
                </div>
                <div class="summary-card" style="background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%);">
                    <h3>NOT APPLICABLE</h3>
                    <div class="number">$totalNA</div>
                    <div>$naPercent% of total</div>
                </div>
            </div>
        </div>
        
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Data for the pie chart
            var data = [
                { label: 'Not a Finding', value: $totalNotAFinding, color: '#27ae60' },
                { label: 'Open', value: $totalOpen, color: '#e74c3c' },
                { label: 'Not Reviewed', value: $totalNotReviewed, color: '#f39c12' },
                { label: 'Not Applicable', value: $totalNA, color: '#95a5a6' }
            ];
            
            var total = data.reduce(function(sum, item) { return sum + item.value; }, 0);
            
            if (total === 0) {
                // If no data, show a message
                document.getElementById('complianceChart').innerHTML = '<text x="200" y="200" text-anchor="middle" fill="var(--text-primary)" font-size="16">No data available</text>';
                return;
            }
            
            var svg = document.getElementById('complianceChart');
            var centerX = 200;
            var centerY = 200;
            var radius = 150;
            var currentAngle = -90; // Start at top
            
            // Create pie slices
            data.forEach(function(item) {
                if (item.value === 0) return;
                
                var sliceAngle = (item.value / total) * 360;
                var startAngle = currentAngle;
                var endAngle = currentAngle + sliceAngle;
                
                // Convert to radians
                var startRad = startAngle * Math.PI / 180;
                var endRad = endAngle * Math.PI / 180;
                
                // Calculate coordinates
                var x1 = centerX + radius * Math.cos(startRad);
                var y1 = centerY + radius * Math.sin(startRad);
                var x2 = centerX + radius * Math.cos(endRad);
                var y2 = centerY + radius * Math.sin(endRad);
                
                // Large arc flag
                var largeArc = sliceAngle > 180 ? 1 : 0;
                
                // Create path
                var pathData = [
                    'M', centerX, centerY,
                    'L', x1, y1,
                    'A', radius, radius, 0, largeArc, 1, x2, y2,
                    'Z'
                ].join(' ');
                
                var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                path.setAttribute('d', pathData);
                path.setAttribute('fill', item.color);
                path.setAttribute('stroke', getComputedStyle(document.body).getPropertyValue('--bg-primary'));
                path.setAttribute('stroke-width', '2');
                
                // Add tooltip on hover
                var title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
                var percentage = ((item.value / total) * 100).toFixed(1);
                title.textContent = item.label + ': ' + item.value + ' (' + percentage + '%)';
                path.appendChild(title);
                
                // Add hover effect
                path.style.cursor = 'pointer';
                path.addEventListener('mouseenter', function() {
                    this.style.opacity = '0.8';
                });
                path.addEventListener('mouseleave', function() {
                    this.style.opacity = '1';
                });
                
                svg.appendChild(path);
                
                currentAngle = endAngle;
            });
            
            // Store the regenerate function for dark mode toggle
            window.regeneratePieChart = function() {
                // Clear existing paths
                while (svg.firstChild) {
                    svg.removeChild(svg.firstChild);
                }
                
                // Regenerate with new colors
                currentAngle = -90;
                data.forEach(function(item) {
                    if (item.value === 0) return;
                    
                    var sliceAngle = (item.value / total) * 360;
                    var startAngle = currentAngle;
                    var endAngle = currentAngle + sliceAngle;
                    
                    var startRad = startAngle * Math.PI / 180;
                    var endRad = endAngle * Math.PI / 180;
                    
                    var x1 = centerX + radius * Math.cos(startRad);
                    var y1 = centerY + radius * Math.sin(startRad);
                    var x2 = centerX + radius * Math.cos(endRad);
                    var y2 = centerY + radius * Math.sin(endRad);
                    
                    var largeArc = sliceAngle > 180 ? 1 : 0;
                    
                    var pathData = [
                        'M', centerX, centerY,
                        'L', x1, y1,
                        'A', radius, radius, 0, largeArc, 1, x2, y2,
                        'Z'
                    ].join(' ');
                    
                    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                    path.setAttribute('d', pathData);
                    path.setAttribute('fill', item.color);
                    path.setAttribute('stroke', getComputedStyle(document.body).getPropertyValue('--bg-primary'));
                    path.setAttribute('stroke-width', '2');
                    
                    var title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
                    var percentage = ((item.value / total) * 100).toFixed(1);
                    title.textContent = item.label + ': ' + item.value + ' (' + percentage + '%)';
                    path.appendChild(title);
                    
                    path.style.cursor = 'pointer';
                    path.addEventListener('mouseenter', function() {
                        this.style.opacity = '0.8';
                    });
                    path.addEventListener('mouseleave', function() {
                        this.style.opacity = '1';
                    });
                    
                    svg.appendChild(path);
                    currentAngle = endAngle;
                });
            };
        });
        </script>
"@        <h2>Open Findings by Severity</h2>
        <table class="stats-table">
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage of Total</th>
            </tr>
            <tr>
                <td class="severity-high">CAT I</td>
                <td>$totalHighOpen</td>
                <td>$(if ($totalVulns -gt 0) { [math]::Round(($totalHighOpen / $totalVulns) * 100, 1) } else { 0 })%</td>
            </tr>
            <tr>
                <td class="severity-medium">CAT II</td>
                <td>$totalMediumOpen</td>
                <td>$(if ($totalVulns -gt 0) { [math]::Round(($totalMediumOpen / $totalVulns) * 100, 1) } else { 0 })%</td>
            </tr>
            <tr>
                <td class="severity-low">CAT III</td>
                <td>$totalLowOpen</td>
                <td>$(if ($totalVulns -gt 0) { [math]::Round(($totalLowOpen / $totalVulns) * 100, 1) } else { 0 })%</td>
            </tr>
        </table>
"@

# Create STIG Summary Table with Severity (removed Total Checks column)
$html += "<h2>Summary by STIG</h2>"

# Group by STIG Title from vulnerabilities (not checklist-level) to capture all STIGs
$stigSummary = @{}

foreach ($checklist in $allChecklists) {
    foreach ($vuln in $checklist.Vulns) {
        $stigTitle = $vuln.STIGTitle
        
        if (-not $stigSummary.ContainsKey($stigTitle)) {
            $stigSummary[$stigTitle] = @{
                CatI = 0
                CatII = 0
                CatIII = 0
            }
        }
        
        # Count open findings by severity
        if ($vuln.Status -eq "Open") {
            if ($vuln.Severity -eq "high") {
                $stigSummary[$stigTitle].CatI += 1
            }
            elseif ($vuln.Severity -eq "medium") {
                $stigSummary[$stigTitle].CatII += 1
            }
            elseif ($vuln.Severity -eq "low") {
                $stigSummary[$stigTitle].CatIII += 1
            }
        }
    }
}

$html += @"
        <table class="stats-table">
            <tr>
                <th>STIG Title</th>
                <th>CAT I Open</th>
                <th>CAT II Open</th>
                <th>CAT III Open</th>
            </tr>
"@

foreach ($stigTitle in ($stigSummary.Keys | Sort-Object)) {
    $stats = $stigSummary[$stigTitle]
    
    $html += @"
            <tr>
                <td>$stigTitle</td>
                <td class="severity-high">$($stats.CatI)</td>
                <td class="severity-medium">$($stats.CatII)</td>
                <td class="severity-low">$($stats.CatIII)</td>
            </tr>
"@
}

$html += @"
        </table>
"@

# Add individual checklist details (collapsible with new styling)
$html += @"
        <div class="section-wrapper">
            <div class="section-header" onclick="toggleSection('individual-checklists')">
                <h2>Individual Checklist Details</h2>
                <span class="collapse-icon">&#9660;</span>
            </div>
            <div class="section-body" id="individual-checklists">
"@

$checklistIndex = 0
foreach ($checklist in $allChecklists) {
    $open = ($checklist.Vulns | Where-Object { $_.Status -eq "Open" }).Count
    $pass = ($checklist.Vulns | Where-Object { $_.Status -eq "NotAFinding" }).Count
    $notReviewed = ($checklist.Vulns | Where-Object { $_.Status -eq "Not_Reviewed" }).Count
    $na = ($checklist.Vulns | Where-Object { $_.Status -eq "Not_Applicable" }).Count
    $total = $checklist.Vulns.Count
    
    $html += @"
        <div class="checklist-section">
            <div class="checklist-header" onclick="toggleChecklist($checklistIndex)">
                <div>
                    <h3>$($checklist.STIGTitle)</h3>
                    <div class="checklist-info">
                        <span><strong>File:</strong> $($checklist.FileName)</span>
                        <span><strong>Host:</strong> $($checklist.HostName)</span>
                        <span><strong>IP:</strong> $($checklist.HostIP)</span>
                        <span><strong>Version:</strong> $($checklist.Version)</span>
                    </div>
                </div>
                <span class="collapse-icon">&#9660;</span>
            </div>
            <div class="checklist-body" id="checklist-$checklistIndex">
                <table class="stats-table">
                    <tr>
                        <th>Status</th>
                        <th>Count</th>
                        <th>Percentage</th>
                        <th>Details</th>
                    </tr>
                    <tr>
                        <td><span class="status-notafinding">Not a Finding</span></td>
                        <td>$pass</td>
                        <td>$(if ($total -gt 0) { [math]::Round(($pass / $total) * 100, 1) } else { 0 })%</td>
                        <td></td>
                    </tr>
                    <tr class="expandable-row" onclick="toggleExpanded('open-$checklistIndex')">
                        <td><span class="status-open">Open</span></td>
                        <td>$open</td>
                        <td>$(if ($total -gt 0) { [math]::Round(($open / $total) * 100, 1) } else { 0 })%</td>
                        <td>$(if ($open -gt 0) { "&#9654; View Rules" } else { "" })</td>
                    </tr>
"@
    
    # Add expandable section for open findings
    if ($open -gt 0) {
        $html += @"
                    <tr>
                        <td colspan="4">
                            <div class="expanded-content" id="open-$checklistIndex">
"@
        
        $openVulns = $checklist.Vulns | Where-Object { $_.Status -eq "Open" } | Sort-Object { 
            switch ($_.Severity) {
                "high" { 1 }
                "medium" { 2 }
                "low" { 3 }
                default { 4 }
            }
        }
        
        foreach ($vuln in $openVulns) {
            $findingId = "open-$($checklist.HostName)-$($vuln.VulnID)" -replace '\s','-'
            $severityLabel = switch ($vuln.Severity) {
                "high" { "CAT I" }
                "medium" { "CAT II" }
                "low" { "CAT III" }
                default { $vuln.Severity }
            }
            $tabId = switch ($vuln.Severity) {
                "high" { "cat1-findings" }
                "medium" { "cat2-findings" }
                "low" { "cat3-findings" }
                default { "cat1-findings" }
            }
            $html += "                                <a onclick=`"navigateToFinding('$findingId', '$tabId', 'all-open-findings')`" class='rule-link'>$($vuln.VulnID) - $($vuln.RuleTitle) [$severityLabel]</a>`n"
        }
        
        $html += @"
                            </div>
                        </td>
                    </tr>
"@
    }
    
    $html += @"
                    <tr class="expandable-row" onclick="toggleExpanded('notreviewed-$checklistIndex')">
                        <td><span class="status-notreviewed">Not Reviewed</span></td>
                        <td>$notReviewed</td>
                        <td>$(if ($total -gt 0) { [math]::Round(($notReviewed / $total) * 100, 1) } else { 0 })%</td>
                        <td>$(if ($notReviewed -gt 0) { "&#9654; View Rules" } else { "" })</td>
                    </tr>
"@
    
    # Add expandable section for not reviewed
    if ($notReviewed -gt 0) {
        $html += @"
                    <tr>
                        <td colspan="4">
                            <div class="expanded-content" id="notreviewed-$checklistIndex">
"@
        
        $notReviewedVulns = $checklist.Vulns | Where-Object { $_.Status -eq "Not_Reviewed" }
        
        foreach ($vuln in $notReviewedVulns) {
            $findingId = "notreviewed-$($checklist.HostName)-$($vuln.VulnID)" -replace '\s','-'
            $html += "                                <a onclick=`"navigateToFinding('$findingId', 'notreviewed-findings', 'all-open-findings')`" class='rule-link'>$($vuln.VulnID) - $($vuln.RuleTitle)</a>`n"
        }
        
        $html += @"
                            </div>
                        </td>
                    </tr>
"@
    }
    
    $html += @"
                    <tr>
                        <td><span class="status-notapplicable">Not Applicable</span></td>
                        <td>$na</td>
                        <td>$(if ($total -gt 0) { [math]::Round(($na / $total) * 100, 1) } else { 0 })%</td>
                        <td></td>
                    </tr>
                </table>
            </div>
        </div>
"@
    
    $checklistIndex++
}

$html += @"
            </div>
        </div>
"@

# Add Open Findings and Not Reviewed with Tabs and alternating backgrounds
$html += @"
        <div class="all-open-findings-section">
            <div class="all-open-findings-header" onclick="toggleAllOpenFindings()">
                <h2>All Open Findings & Not Reviewed Items</h2>
                <span class="collapse-icon">&#9660;</span>
            </div>
            <div class="all-open-findings-body" id="all-open-findings">
"@

# Create tabs - always show them even if counts are 0
$html += @"
        <div class="tabs">
            <button class="tab-button active" onclick="openTab(event, 'cat1-findings')">CAT I ($totalHighOpen)</button>
            <button class="tab-button" onclick="openTab(event, 'cat2-findings')">CAT II ($totalMediumOpen)</button>
            <button class="tab-button" onclick="openTab(event, 'cat3-findings')">CAT III ($totalLowOpen)</button>
            <button class="tab-button" onclick="openTab(event, 'notreviewed-findings')">Not Reviewed ($totalNotReviewed)</button>
        </div>
"@

if ($totalOpen -eq 0 -and $totalNotReviewed -eq 0) {
    $html += "<p style='color: #27ae60; font-weight: bold; font-size: 18px;'>Excellent! No open findings or items requiring review.</p>"
} else {
    
    # CAT I Tab
    $html += '<div id="cat1-findings" class="tab-content active">'
    
    if ($totalHighOpen -eq 0) {
        $html += "<p style='color: #27ae60; font-weight: bold;'>No CAT I findings.</p>"
    } else {
        $checklistGroupIndex = 0
        foreach ($checklist in $allChecklists) {
            $cat1Findings = $checklist.Vulns | Where-Object { $_.Status -eq "Open" -and $_.Severity -eq "high" }
            
            if ($cat1Findings.Count -gt 0) {
                $altBgClass = if ($checklistGroupIndex % 2 -eq 1) { "alt-bg" } else { "" }
                $html += "<div class='checklist-group $altBgClass'>"
                $html += "<h3 style='color: #2c3e50;'>$($checklist.FileName) - $($checklist.HostName)</h3>"
                
                foreach ($finding in $cat1Findings) {
                    $findingId = "open-$($checklist.HostName)-$($finding.VulnID)" -replace '\s','-'
                    $html += @"
                    <div class="finding-card severity-high" id="$findingId">
                        <div class="finding-header">
                            <div class="finding-title">$($finding.VulnID): $($finding.RuleTitle)</div>
                            <span class="severity-high">CAT I</span>
                        </div>
                        <div class="finding-details">
                            <strong>Rule ID:</strong> $($finding.RuleID)
                        </div>
                        <div class="finding-details">
                            <strong>STIG:</strong> $($finding.STIGTitle)
                        </div>
                        <div class="finding-details">
                            <strong>Group:</strong> $($finding.GroupTitle)
                        </div>
"@
                    if ($finding.FindingDetails) {
                        $html += @"
                        <div class="finding-details">
                            <strong>Finding Details:</strong><br>
                            $(([System.Web.HttpUtility]::HtmlEncode($finding.FindingDetails) -replace "`n", "<br>"))
                        </div>
"@
                    }
                    
                    if ($finding.Comments) {
                        $html += @"
                        <div class="finding-details">
                            <strong>Comments:</strong><br>
                            $(([System.Web.HttpUtility]::HtmlEncode($finding.Comments) -replace "`n", "<br>"))
                        </div>
"@
                    }
                    
                    $html += "</div>"
                }
                
                $html += "</div>"
                $checklistGroupIndex++
            }
        }
    }
    
    $html += '</div>' # End CAT I tab
    
    # CAT II Tab
    $html += '<div id="cat2-findings" class="tab-content">'
    
    if ($totalMediumOpen -eq 0) {
        $html += "<p style='color: #27ae60; font-weight: bold;'>No CAT II findings.</p>"
    } else {
        $checklistGroupIndex = 0
        foreach ($checklist in $allChecklists) {
            $cat2Findings = $checklist.Vulns | Where-Object { $_.Status -eq "Open" -and $_.Severity -eq "medium" }
            
            if ($cat2Findings.Count -gt 0) {
                $altBgClass = if ($checklistGroupIndex % 2 -eq 1) { "alt-bg" } else { "" }
                $html += "<div class='checklist-group $altBgClass'>"
                $html += "<h3 style='color: #2c3e50;'>$($checklist.FileName) - $($checklist.HostName)</h3>"
                
                foreach ($finding in $cat2Findings) {
                    $findingId = "open-$($checklist.HostName)-$($finding.VulnID)" -replace '\s','-'
                    $html += @"
                    <div class="finding-card severity-medium" id="$findingId">
                        <div class="finding-header">
                            <div class="finding-title">$($finding.VulnID): $($finding.RuleTitle)</div>
                            <span class="severity-medium">CAT II</span>
                        </div>
                        <div class="finding-details">
                            <strong>Rule ID:</strong> $($finding.RuleID)
                        </div>
                        <div class="finding-details">
                            <strong>STIG:</strong> $($finding.STIGTitle)
                        </div>
                        <div class="finding-details">
                            <strong>Group:</strong> $($finding.GroupTitle)
                        </div>
"@
                    if ($finding.FindingDetails) {
                        $html += @"
                        <div class="finding-details">
                            <strong>Finding Details:</strong><br>
                            $(([System.Web.HttpUtility]::HtmlEncode($finding.FindingDetails) -replace "`n", "<br>"))
                        </div>
"@
                    }
                    
                    if ($finding.Comments) {
                        $html += @"
                        <div class="finding-details">
                            <strong>Comments:</strong><br>
                            $(([System.Web.HttpUtility]::HtmlEncode($finding.Comments) -replace "`n", "<br>"))
                        </div>
"@
                    }
                    
                    $html += "</div>"
                }
                
                $html += "</div>"
                $checklistGroupIndex++
            }
        }
    }
    
    $html += '</div>' # End CAT II tab
    
    # CAT III Tab
    $html += '<div id="cat3-findings" class="tab-content">'
    
    if ($totalLowOpen -eq 0) {
        $html += "<p style='color: #27ae60; font-weight: bold;'>No CAT III findings.</p>"
    } else {
        $checklistGroupIndex = 0
        foreach ($checklist in $allChecklists) {
            $cat3Findings = $checklist.Vulns | Where-Object { $_.Status -eq "Open" -and $_.Severity -eq "low" }
            
            if ($cat3Findings.Count -gt 0) {
                $altBgClass = if ($checklistGroupIndex % 2 -eq 1) { "alt-bg" } else { "" }
                $html += "<div class='checklist-group $altBgClass'>"
                $html += "<h3 style='color: #2c3e50;'>$($checklist.FileName) - $($checklist.HostName)</h3>"
                
                foreach ($finding in $cat3Findings) {
                    $findingId = "open-$($checklist.HostName)-$($finding.VulnID)" -replace '\s','-'
                    $html += @"
                    <div class="finding-card severity-low" id="$findingId">
                        <div class="finding-header">
                            <div class="finding-title">$($finding.VulnID): $($finding.RuleTitle)</div>
                            <span class="severity-low">CAT III</span>
                        </div>
                        <div class="finding-details">
                            <strong>Rule ID:</strong> $($finding.RuleID)
                        </div>
                        <div class="finding-details">
                            <strong>STIG:</strong> $($finding.STIGTitle)
                        </div>
                        <div class="finding-details">
                            <strong>Group:</strong> $($finding.GroupTitle)
                        </div>
"@
                    if ($finding.FindingDetails) {
                        $html += @"
                        <div class="finding-details">
                            <strong>Finding Details:</strong><br>
                            $(([System.Web.HttpUtility]::HtmlEncode($finding.FindingDetails) -replace "`n", "<br>"))
                        </div>
"@
                    }
                    
                    if ($finding.Comments) {
                        $html += @"
                        <div class="finding-details">
                            <strong>Comments:</strong><br>
                            $(([System.Web.HttpUtility]::HtmlEncode($finding.Comments) -replace "`n", "<br>"))
                        </div>
"@
                    }
                    
                    $html += "</div>"
                }
                
                $html += "</div>"
                $checklistGroupIndex++
            }
        }
    }
    
    $html += '</div>' # End CAT III tab
    
    # Not Reviewed Tab
    $html += '<div id="notreviewed-findings" class="tab-content">'
    
    if ($totalNotReviewed -eq 0) {
        $html += "<p style='color: #27ae60; font-weight: bold;'>No items requiring review.</p>"
    } else {
        $checklistGroupIndex = 0
        foreach ($checklist in $allChecklists) {
            $notReviewedItems = $checklist.Vulns | Where-Object { $_.Status -eq "Not_Reviewed" }
            
            if ($notReviewedItems.Count -gt 0) {
                $altBgClass = if ($checklistGroupIndex % 2 -eq 1) { "alt-bg" } else { "" }
                $html += "<div class='checklist-group $altBgClass'>"
                $html += "<h3 style='color: #2c3e50;'>$($checklist.FileName) - $($checklist.HostName)</h3>"
                
                foreach ($item in $notReviewedItems) {
                    $findingId = "notreviewed-$($checklist.HostName)-$($item.VulnID)" -replace '\s','-'
                    $html += @"
                    <div class="finding-card" id="$findingId">
                        <div class="finding-header">
                            <div class="finding-title">$($item.VulnID): $($item.RuleTitle)</div>
                            <span class="status-notreviewed">Not Reviewed</span>
                        </div>
                        <div class="finding-details">
                            <strong>Rule ID:</strong> $($item.RuleID)
                        </div>
                        <div class="finding-details">
                            <strong>STIG:</strong> $($item.STIGTitle)
                        </div>
                        <div class="finding-details">
                            <strong>Group:</strong> $($item.GroupTitle)
                        </div>
"@
                    if ($item.Comments) {
                        $html += @"
                        <div class="finding-details">
                            <strong>Comments:</strong><br>
                            $(([System.Web.HttpUtility]::HtmlEncode($item.Comments) -replace "`n", "<br>"))
                        </div>
"@
                    }
                    
                    $html += "</div>"
                }
                
                $html += "</div>"
                $checklistGroupIndex++
            }
        }
    }
    
    $html += '</div>' # End Not Reviewed tab
}

$html += @"
            </div>
        </div>
"@

# Create Unique Open Findings by STIG with new styling
$html += @"
        <div class="section-wrapper">
            <div class="section-header" onclick="toggleSection('unique-findings')">
                <h2>Unique Open Findings by STIG</h2>
                <span class="collapse-icon">&#9660;</span>
            </div>
            <div class="section-body" id="unique-findings">
"@

# Group all vulnerabilities by VulnID and STIG
$uniqueFindings = @{}

foreach ($checklist in $allChecklists) {
    foreach ($vuln in $checklist.Vulns) {
        if ($vuln.Status -eq "Open") {
            $key = "$($vuln.STIGTitle)|$($vuln.VulnID)"
            
            if (-not $uniqueFindings.ContainsKey($key)) {
                $uniqueFindings[$key] = @{
                    STIGTitle = $vuln.STIGTitle
                    VulnID = $vuln.VulnID
                    RuleTitle = $vuln.RuleTitle
                    Severity = $vuln.Severity
                    Hosts = @()
                }
            }
            
            $uniqueFindings[$key].Hosts += @{
                HostName = $checklist.HostName
                HostIP = $checklist.HostIP
                FileName = $checklist.FileName
            }
        }
    }
}

# Group by STIG
$stigGroups = @{}
foreach ($key in $uniqueFindings.Keys) {
    $finding = $uniqueFindings[$key]
    $stigTitle = $finding.STIGTitle
    
    if (-not $stigGroups.ContainsKey($stigTitle)) {
        $stigGroups[$stigTitle] = @()
    }
    
    $stigGroups[$stigTitle] += $finding
}

$stigGroupIndex = 0
foreach ($stigTitle in ($stigGroups.Keys | Sort-Object)) {
    $findings = $stigGroups[$stigTitle] | Sort-Object { 
        switch ($_.Severity) {
            "high" { 1 }
            "medium" { 2 }
            "low" { 3 }
            default { 4 }
        }
    }
    
    $html += @"
        <div class="collapsible-section">
            <div class="collapsible-header" onclick="toggleCollapsible('stig-group-$stigGroupIndex')">
                <h3>$stigTitle ($($findings.Count) unique findings)</h3>
                <span class="collapse-icon">&#9660;</span>
            </div>
            <div class="collapsible-content" id="stig-group-$stigGroupIndex">
"@
    
    $findingIndex = 0
    foreach ($finding in $findings) {
        $severityClass = $finding.Severity.ToLower()
        $severityLabel = switch ($finding.Severity) {
            "high" { "CAT I" }
            "medium" { "CAT II" }
            "low" { "CAT III" }
            default { $finding.Severity }
        }
        
        $html += @"
                <div class="collapsible-section" style="margin: 10px 0;">
                    <div class="nested-finding-header" onclick="toggleCollapsible('finding-$stigGroupIndex-$findingIndex')">
                        <div>
                            <strong class="severity-$severityClass">[$severityLabel]</strong> $($finding.VulnID): $($finding.RuleTitle)
                        </div>
                        <span class="collapse-icon">&#9660;</span>
                    </div>
                    <div class="collapsible-content" id="finding-$stigGroupIndex-$findingIndex">
                        <h4>Affected Hosts ($($finding.Hosts.Count))</h4>
                        <div class="host-list">
"@
        
        foreach ($hostInfo in $finding.Hosts) {
            $html += "                            <div class='host-item'><strong>$($hostInfo.HostName)</strong> ($($hostInfo.HostIP)) - $($hostInfo.FileName)</div>`n"
        }
        
        $html += @"
                        </div>
                    </div>
                </div>
"@
        
        $findingIndex++
    }
    
    $html += @"
            </div>
        </div>
"@
    
    $stigGroupIndex++
}

$html += @"
            </div>
        </div>
"@

$html += @"
            </div>
        </div>
"@

$html += @"
        <div class="timestamp">
            Report generated on $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")
        </div>
"@

# Add classification footer if provided
if ($ClassificationText) {
    $html += "        <div class=`"classification-footer`">$ClassificationText</div>`n"
}

$html += @"
    </div>
"@

# Add bottom banner if provided
if ($BottomBannerText) {
    $html += "    <div class=`"banner`" style=`"background-color: $BottomBannerBgColor; color: $BottomBannerTextColor;`">$BottomBannerText</div>`n"
}

$html += @"
    
    <script>
        function toggleDarkMode() {
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
            
            // Regenerate pie chart with new border colors
            if (window.regeneratePieChart) {
                window.regeneratePieChart();
            }
        }
        
        // Check for saved dark mode preference
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
        }
        
        function openTab(evt, tabName) {
            var i, tabcontent, tabbuttons;
            
            // Hide all tab content
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            
            // Remove active class from all buttons
            tabbuttons = document.getElementsByClassName("tab-button");
            for (i = 0; i < tabbuttons.length; i++) {
                tabbuttons[i].classList.remove("active");
            }
            
            // Show the current tab and mark button as active
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }
        
        function toggleChecklist(index) {
            var content = document.getElementById('checklist-' + index);
            var icon = event.currentTarget.querySelector('.collapse-icon');
            
            if (content.classList.contains('active')) {
                content.classList.remove('active');
                icon.classList.remove('expanded');
            } else {
                content.classList.add('active');
                icon.classList.add('expanded');
            }
        }
        
        function toggleExpanded(id) {
            var content = document.getElementById(id);
            
            if (content.classList.contains('active')) {
                content.classList.remove('active');
            } else {
                content.classList.add('active');
            }
            
            event.stopPropagation();
        }
        
        function toggleCollapsible(id) {
            var content = document.getElementById(id);
            var icon = event.currentTarget.querySelector('.collapse-icon');
            
            if (content.classList.contains('active')) {
                content.classList.remove('active');
                icon.classList.remove('expanded');
            } else {
                content.classList.add('active');
                icon.classList.add('expanded');
            }
        }
        
        function toggleAllOpenFindings() {
            var content = document.getElementById('all-open-findings');
            var icon = event.currentTarget.querySelector('.collapse-icon');
            
            if (content.classList.contains('active')) {
                content.classList.remove('active');
                icon.classList.remove('expanded');
            } else {
                content.classList.add('active');
                icon.classList.add('expanded');
            }
        }
        
        function toggleSection(id) {
            var content = document.getElementById(id);
            var icon = event.currentTarget.querySelector('.collapse-icon');
            
            if (content.classList.contains('active')) {
                content.classList.remove('active');
                icon.classList.remove('expanded');
            } else {
                content.classList.add('active');
                icon.classList.add('expanded');
            }
        }
        
        function navigateToFinding(findingId, tabId, sectionId) {
            // First, expand the section if collapsed
            var sectionBody = document.getElementById(sectionId);
            var sectionIcon = sectionBody.previousElementSibling.querySelector('.collapse-icon');
            if (!sectionBody.classList.contains('active')) {
                sectionBody.classList.add('active');
                sectionIcon.classList.add('expanded');
            }
            
            // Switch to the correct tab
            var tabButtons = document.getElementsByClassName("tab-button");
            var tabContents = document.getElementsByClassName("tab-content");
            
            // Deactivate all tabs
            for (var i = 0; i < tabButtons.length; i++) {
                tabButtons[i].classList.remove("active");
            }
            for (var i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove("active");
            }
            
            // Activate the correct tab
            var targetTab = document.getElementById(tabId);
            if (targetTab) {
                targetTab.classList.add("active");
                
                // Activate the corresponding button
                var buttons = document.querySelectorAll('.tab-button');
                buttons.forEach(function(btn) {
                    if (btn.textContent.includes('CAT I') && tabId === 'cat1-findings') {
                        btn.classList.add('active');
                    } else if (btn.textContent.includes('CAT II') && tabId === 'cat2-findings') {
                        btn.classList.add('active');
                    } else if (btn.textContent.includes('CAT III') && tabId === 'cat3-findings') {
                        btn.classList.add('active');
                    } else if (btn.textContent.includes('Not Reviewed') && tabId === 'notreviewed-findings') {
                        btn.classList.add('active');
                    }
                });
            }
            
            // Scroll to the finding with highlight
            var element = document.getElementById(findingId);
            if (element) {
                element.scrollIntoView({ behavior: 'smooth', block: 'start' });
                element.classList.add('highlight');
                setTimeout(function() {
                    element.classList.remove('highlight');
                }, 2000);
            }
        }
    </script>
</body>
</html>
"@

# Save HTML file
$html | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host "`nReport generated successfully!" -ForegroundColor Green
Write-Host "Output file: $OutputFile" -ForegroundColor Cyan
Write-Host "`nSummary:" -ForegroundColor Yellow
Write-Host "  Total Checklists: $($allChecklists.Count)"
Write-Host "  Total Checks: $totalVulns"
Write-Host "  Open Findings: $totalOpen (CAT I: $totalHighOpen, CAT II: $totalMediumOpen, CAT III: $totalLowOpen)"
Write-Host "  Pass Rate: $passPercent%"
