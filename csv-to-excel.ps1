# CSV to Excel Converter Script
# Converts three CSV files into a single Excel workbook with separate tabs
# No internet connection or third-party modules required

param(
    [string]$Csv1Path = "file1.csv",
    [string]$Csv2Path = "file2.csv",
    [string]$Csv3Path = "file3.csv",
    [string]$OutputPath = "output.xlsx",
    [string]$Sheet1Name = "Sheet1",
    [string]$Sheet2Name = "Sheet2",
    [string]$Sheet3Name = "Sheet3"
)

# Function to import CSV and write to Excel worksheet
function Import-CsvToWorksheet {
    param(
        [string]$CsvPath,
        [object]$Worksheet,
        [string]$SheetName
    )
    
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return $false
    }
    
    Write-Host "Processing $CsvPath..."
    
    # Read CSV file
    $csvData = Import-Csv -Path $CsvPath
    
    if ($csvData.Count -eq 0) {
        Write-Warning "No data found in $CsvPath"
        return $true
    }
    
    # Set worksheet name
    $Worksheet.Name = $SheetName
    
    # Get column headers
    $headers = $csvData[0].PSObject.Properties.Name
    
    # Write headers
    for ($col = 0; $col -lt $headers.Count; $col++) {
        $Worksheet.Cells.Item(1, $col + 1) = $headers[$col]
        $Worksheet.Cells.Item(1, $col + 1).Font.Bold = $true
    }
    
    # Write data rows
    for ($row = 0; $row -lt $csvData.Count; $row++) {
        for ($col = 0; $col -lt $headers.Count; $col++) {
            $Worksheet.Cells.Item($row + 2, $col + 1) = $csvData[$row].$($headers[$col])
        }
    }
    
    # Auto-fit columns
    $usedRange = $Worksheet.UsedRange
    $usedRange.EntireColumn.AutoFit() | Out-Null
    
    Write-Host "Successfully imported $CsvPath to worksheet '$SheetName'"
    return $true
}

# Main script execution
try {
    Write-Host "`n=== CSV to Excel Converter ===" -ForegroundColor Cyan
    Write-Host "Output file: $OutputPath`n"
    
    # Create Excel application object
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    
    # Create new workbook
    $workbook = $excel.Workbooks.Add()
    
    # Remove extra default sheets (Excel creates 3 by default in older versions)
    while ($workbook.Worksheets.Count -gt 3) {
        $workbook.Worksheets.Item($workbook.Worksheets.Count).Delete()
    }
    
    # Ensure we have exactly 3 sheets
    while ($workbook.Worksheets.Count -lt 3) {
        $workbook.Worksheets.Add() | Out-Null
    }
    
    # Process each CSV file
    $sheet1 = $workbook.Worksheets.Item(1)
    $success1 = Import-CsvToWorksheet -CsvPath $Csv1Path -Worksheet $sheet1 -SheetName $Sheet1Name
    
    $sheet2 = $workbook.Worksheets.Item(2)
    $success2 = Import-CsvToWorksheet -CsvPath $Csv2Path -Worksheet $sheet2 -SheetName $Sheet2Name
    
    $sheet3 = $workbook.Worksheets.Item(3)
    $success3 = Import-CsvToWorksheet -CsvPath $Csv3Path -Worksheet $sheet3 -SheetName $Sheet3Name
    
    if ($success1 -and $success2 -and $success3) {
        # Save workbook
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        
        # Delete existing file if it exists
        if (Test-Path $fullPath) {
            Remove-Item $fullPath -Force
        }
        
        $workbook.SaveAs($fullPath, 51) # 51 = xlOpenXMLWorkbook (.xlsx)
        Write-Host "`nExcel file created successfully: $fullPath" -ForegroundColor Green
    }
    else {
        Write-Error "One or more CSV files could not be processed."
    }
    
    # Close workbook and Excel
    $workbook.Close($false)
    $excel.Quit()
    
    # Release COM objects
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    
    Write-Host "`nProcess completed!" -ForegroundColor Cyan
}
catch {
    Write-Error "An error occurred: $_"
    
    # Cleanup on error
    if ($workbook) { $workbook.Close($false) }
    if ($excel) { $excel.Quit() }
    
    exit 1
}
