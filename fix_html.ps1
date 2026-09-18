$p='C:\Users\28299\Desktop\modpkica4JAVA\src\modpkica\WebAdmin.java'
$s=[IO.File]::ReadAllText($p,[Text.Encoding]::UTF8)
# 1) P2 结尾：删除 </html> 行（保留 </script></body>）
$idxHtml=$s.IndexOf('        </html>')
Write-Host "html idx=$idxHtml"
if($idxHtml -gt 0){
    $lineStart=$s.LastIndexOf("`n",$idxHtml)+1
    $lineEnd=$s.IndexOf("`n",$idxHtml)
    if($lineEnd -lt 0){ $lineEnd=$s.Length }
    $s=$s.Substring(0,$lineStart)+$s.Substring($lineEnd+1)
    Write-Host 'step1 OK: removed </html> line'
}
# 2) P3 开头：在调试注释行前加 <script>
$anchor='private static final String PAGE_P3 = """'
$i3=$s.IndexOf($anchor)
if($i3 -ge 0){
    $after=$i3+$anchor.Length
    $p3body=$s.Substring($after)
    $nl=$p3body.IndexOf("`n")
    $p3first=$p3body.IndexOf('        // ===== 调试专区')
    Write-Host "p3first=$p3first"
    if($p3first -gt 0){
        $s=$s.Substring(0,$after+$p3first)+'        <script>'+$s.Substring($after+$p3first)
        Write-Host 'step2 OK: <script> inserted'
    }
}
# 3) P3 结尾：在 P3 的 """ 前加 </script></html>
$iEnd=$s.IndexOf($anchor)
$p3tailStart=$s.IndexOf('    """;',$iEnd)
if($p3tailStart -gt 0){
    # 找 P3 结束引号行前最后一个 } 行
    $pre=$s.Substring(0,$p3tailStart)
    $lastClose=$pre.LastIndexOf('        }')
    Write-Host "lastClose=$lastClose tailStart=$p3tailStart"
    if($lastClose -gt 0 -and ($p3tailStart-$lastClose) -lt 200){
        $s=$s.Substring(0,$lastClose+('        }').Length)+"`n        </script>`n        </html>"+$s.Substring($p3tailStart)
        Write-Host 'step3 OK: </script></html> inserted'
    }
}
[IO.File]::WriteAllText($p,$s,(New-Object Text.UTF8Encoding $false))
Write-Host 'written'