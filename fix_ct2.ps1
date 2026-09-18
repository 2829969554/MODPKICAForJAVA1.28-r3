$p='C:\Users\28299\Desktop\modpkica4JAVA\src\modpkica\WebAdmin.java'
$s=[IO.File]::ReadAllText($p,[Text.Encoding]::UTF8)

$o1 = "tr.innerHTML = '<td>' + k.index + '</td><td>' + esc(k.description) + '</td>' +"
$n1 = "tr.innerHTML = '<td><div>' + k.index + '</div></td>' +"
$o1b = "'<td style=\"font-family:var(--mono);font-size:12px;word-break:break-all\">' + esc(k.logId) + '</td>' +"
$n1b = "'<td><div style=\"font-family:var(--mono);font-size:12px\">' + esc(k.logId) + '</div></td>' +"
$o1c = "'<td style=\"' + stCls + '\">' + esc(stTxt) + '</td><td>' + esc(k.created) + '</td>' +"
$n1c = "'<td><div style=\"' + stCls + '\">' + esc(stTxt) + '</div></td>' +"
$o1d = "'<td><button class=\"ghost\" onclick=\"delCtKey(\\'' + esc(k.logId) + '\\')\">删除</button> ' +"
$n1d = "'<td><div><button class=\"ghost\" onclick=\"delCtKey(\\'' + esc(k.logId) + '\\')\">删除</button> ' +"
$o1e = "'<button class=\"ghost\" onclick=\"setCtState(\\'' + esc(k.logId) + '\\',\\'disable\\')\">暂停</button></td>';"
$n1e = "'<button class=\"ghost\" onclick=\"setCtState(\\'' + esc(k.logId) + '\\',\\'disable\\')\">暂停</button></div></td>';"

$o2 = "tr.innerHTML = '<td style=\"color:var(--dim)\">' + (i + 1) + '</td>' +"
$n2 = "tr.innerHTML = '<td><div style=\"color:var(--dim)\">' + (i + 1) + '</div></td>' +"
$o2b = "'<td style=\"font-family:var(--mono);font-size:12px;word-break:break-all\">' + esc(line) + '</td>';"
$n2b = "'<td><div style=\"font-family:var(--mono);font-size:12px\">' + esc(line) + '</div></td>';"

$checks = @(
  @($o1,$n1,'o1'), @($o1b,$n1b,'o1b'), @($o1c,$n1c,'o1c'), @($o1d,$n1d,'o1d'), @($o1e,$n1e,'o1e'),
  @($o2,$n2,'o2'), @($o2b,$n2b,'o2b')
)
$ok=$true
foreach($pair in $checks){
  $cnt=([regex]::Matches($s,[regex]::Escape($pair[0]))).Count
  Write-Host ("{0} count={1}" -f $pair[2],$cnt)
  if($cnt -eq 1){ $s=$s.Replace($pair[0],$pair[1]) } else { $ok=$false }
}
if($ok){
  [IO.File]::WriteAllText($p,$s,(New-Object Text.UTF8Encoding $false))
  Write-Host 'written'
} else {
  Write-Host 'ABORT - not all anchors found'
}
