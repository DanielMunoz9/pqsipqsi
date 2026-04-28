$base = "C:\Users\Daniel\Desktop\valhala\public"
$files = Get-ChildItem $base -Recurse -Include "*.html","*.js" | Sort-Object Name
$mojiKeys = @("EFBFBD","C3A9","C3A1","C3B3","C3BA","C3AD","C3B1","C3BC","C383","C2A1","C2BF")
"====== REPORTE: EF BF BD (U+FFFD) y Mojibake ======"
"{0,-45} {1,8}  {2}" -f "ARCHIVO","#FFFD","MOJIBAKE DETALLE"
"-"*80
foreach($f in $files){
    $b=[System.IO.File]::ReadAllBytes($f.FullName)
    $hex=($b|ForEach-Object{$_.ToString("X2")})-join""
    $nF=([regex]::Matches($hex,"EFBFBD")).Count
    $mj=@()
    foreach($k in $mojiKeys|Select-Object -Skip 1){
        $n=([regex]::Matches($hex,$k)).Count
        if($n-gt 0){$mj+="$k=$n"}
    }
    $rel=$f.FullName.Replace($base+"\","")
    $flag=if($nF-gt 0 -or $mj.Count-gt 0){"  <-- PROBLEMA"}else{""}
    "{0,-45} {1,8}  {2}{3}" -f $rel,$nF,$(if($mj){$mj -join "  "}else{"-"}),$flag
}
""
"====== FIN ======"
