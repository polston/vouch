# PowerShell AST Reference Parser Worker
# Reads JSON requests from stdin, parses via System.Management.Automation.Language.Parser,
# and writes JSON results to stdout.

$ErrorActionPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

while ($true) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line) { break }
    if ($line.Trim() -eq "") { continue }

    $reqId = "req"
    try {
        $req = ConvertFrom-Json $line -ErrorAction Stop
        $code = $req.code
        if ($req.id) { $reqId = $req.id }

        $errors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors)

        $statements = @()
        $constructs = @()
        $redirects = @()

        # Statement and block construct discovery
        $foreachNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)
        if ($foreachNodes -and $foreachNodes.Count -gt 0) { $constructs += "keyword_foreach" }

        $whileNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.WhileStatementAst] }, $true)
        if ($whileNodes -and $whileNodes.Count -gt 0) { $constructs += "keyword_while" }

        $doNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.DoWhileStatementAst] -or $args[0] -is [System.Management.Automation.Language.DoUntilStatementAst] }, $true)
        if ($doNodes -and $doNodes.Count -gt 0) { $constructs += "keyword_do" }

        $switchNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)
        if ($switchNodes -and $switchNodes.Count -gt 0) { $constructs += "keyword_switch" }

        $trapNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TrapStatementAst] }, $true)
        if ($trapNodes -and $trapNodes.Count -gt 0) { $constructs += "keyword_trap" }

        $classNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)
        if ($classNodes -and $classNodes.Count -gt 0) { $constructs += "keyword_class" }

        $tryNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TryStatementAst] }, $true)
        if ($tryNodes -and $tryNodes.Count -gt 0) { $constructs += "keyword_try" }

        $fnNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        if ($fnNodes -and $fnNodes.Count -gt 0) { $constructs += "function_def" }

        $assignNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
        if ($assignNodes -and $assignNodes.Count -gt 0) {
            foreach ($a in $assignNodes) {
                if ($a.Left.Extent.Text -like "*env:*") {
                    $constructs += "env_assignment"
                } else {
                    $constructs += "assignment"
                }
            }
        }

        # Find all commands across the AST
        $cmdNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
        if ($cmdNodes) {
            foreach ($cmd in $cmdNodes) {
                $cmdName = $cmd.GetCommandName()
                $args = @()
                for ($i = 1; $i -lt $cmd.CommandElements.Count; $i++) {
                    $argElem = $cmd.CommandElements[$i]
                    $args += $argElem.Extent.Text
                    if ($argElem -is [System.Management.Automation.Language.TypeExpressionAst]) {
                        $constructs += "type_literal"
                    }
                }
                $head = if ($cmdName) { $cmdName } else { $cmd.CommandElements[0].Extent.Text }
                $statements += @{
                    head = $head
                    args = @($args)
                }
            }
        }

        # Find all redirections across the AST
        $redirNodes = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.RedirectionAst] }, $true)
        if ($redirNodes) {
            foreach ($r in $redirNodes) {
                if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) {
                    $redirects += $r.Location.Extent.Text
                } else {
                    $redirects += $r.Extent.Text
                }
            }
        }

        $errList = @()
        if ($errors -and $errors.Count -gt 0) {
            foreach ($e in $errors) {
                $errList += $e.Message
            }
            $constructs += "parse_failure"
        }

        $res = @{
            id = $reqId
            commands = @($statements)
            redirects = @($redirects)
            constructs = @($constructs | Select-Object -Unique)
            errors = @($errList)
        }
        $json = ConvertTo-Json -Depth 10 -Compress $res
        [Console]::Out.WriteLine($json)
    } catch {
        $errRes = @{
            id = $reqId
            commands = @()
            redirects = @()
            constructs = @("parse_failure")
            errors = @($_.Exception.Message)
        }
        [Console]::Out.WriteLine((ConvertTo-Json -Depth 10 -Compress $errRes))
    }
}
