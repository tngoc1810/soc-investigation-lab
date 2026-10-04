# PowerShell text: reconstruct, decode, parse, then assess

The public sample in case 003 is a useful counterexample to keyword-driven incident narratives. It contains IEX, WebClient and downloadString, yet the expression is quoted. Version 3 adds static reconstruction and native AST inspection to make that distinction reviewable.

## Evidence and static results

The original public collection has three records: two 4104 script blocks and one 4103 module record. The download-looking block is parsed as supplied; the URL in that text is never visited. PowerShell 7.6.5 reports zero command ASTs, zero member-invocation ASTs and zero parser errors for the quoted block. The recorded module evidence supports the earlier assessment that the expression was printed as text.

This does not prove the complete historical session was benign. The parser version also differs from the historical environment's PowerShell version. Its result is a static syntax check of this supplied text, not execution tracing or a reconstruction of an uncollected runspace.

The public text was also parsed with Windows PowerShell 5.1.26100.9444: zero command nodes, zero member invocations and zero errors. [The separate artifact](../evidence/operations/ast/public-quoted-ps51.ast.json) provides another syntax check; it cannot recreate an unobserved historical session.

## Fragment reconstruction

`soclab/forensics.py` accepts only PowerShell/Operational provider 4104 records. Groups are scoped by source hash, host and ScriptBlockId. This intentionally refuses to assemble one script across independent files merely because a block ID matches. Cross-file collection scope and runspace identity require analyst review.

The constructed five-record experiment has three groups:

| Group | Supplied evidence | Result |
| --- | --- | --- |
| complete-lab | Part 2 arrives before part 1; both agree on total 2 | Complete static text: `Write-Output 'IEX downloadString is text'` |
| missing-lab | Only part 1 of 2 | Missing part 2; full script is absent |
| conflict-lab | Two different texts both claim part 1 of 1 | Conflicting content; full script is absent |

Identical duplicate parts can retain multiple evidence references without repeating their text. Inconsistent totals, invalid part metadata, conflicts, missing parts and excessive length prevent a complete result. The maximum reconstructed text is 262,144 characters, with at most 1,000 declared parts.

The design does not treat an incomplete reconstruction as a harmless script. It reports the gap and keeps the references. A same-ID repeated block across a long collection is another reason to inspect context: source/host/ID grouping is conservative, but it is not authenticated runspace attribution.

## Decode without executing

The encoded-command helper recognizes selected exact PowerShell host switches before `-File` or `-Command`, validates Base64, bounds the decoded input and decodes strict UTF-16LE. It produces text and a byte hash. It never invokes PowerShell with that recovered content.

The demonstrated encoded fixture contains only `Write-Output 'inert command AST fixture'`. Its decoded text matches that fixture and parses as one command AST. Malformed Base64, odd-length UTF-16 input and encoded-looking strings after a script-content switch fail inspection rather than becoming executed commands.

This is not a comprehensive Windows command-line parser. Unusual quoting, abbreviated switches, alternate code pages or other obfuscation can fall outside its supported forms. A decode failure is an analysis gap, not a benign verdict.

## Native AST inspection

`scripts/inspect_ast.ps1` reads a text file and calls `System.Management.Automation.Language.Parser.ParseInput`. It reports CommandAst, InvokeMemberExpressionAst, string literals and parser errors. It neither dot-sources the file nor runs the recovered text. Complete reconstructed and decoded fixtures each produce one inert Write-Output command; the public quoted expression produces neither command nor member invocation.

Even a real command node can appear in an unused function or unreachable branch. Conversely, one collected script block may lack the larger context needed to understand interpolation or invocation. The right conclusion connects syntax with process, network, module and session evidence rather than calling an AST node proof of runtime behavior.

## Analyst decision

For the public case, keep the keyword lead, explain the quoting and request full context before a download/execution verdict. For the fragmented experiment, report exactly which blocks can be reconstructed and which cannot. For the encoded fixture, describe decoding and static parsing as inspection, not successful attack reproduction.

Results, source references and parser-version metadata are in [forensics.json](../evidence/operations/forensics.json) and [the AST evidence directory](../evidence/operations/ast). The original case report remains the broader assessment: [CASE-003](../cases/003-powershell-string/report.md).
