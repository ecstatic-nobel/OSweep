#!/opt/splunk/bin/python


queries = {
    "automatic" : "task.method:automatic",
    "manual"    : "!task.method:automatic",
    "certstream": "(task.source:certstream-idn OR \
                   task.source:certstream-suspicious)",
    "openphish" : "task.source:openphish",
    "phishtank" : "task.source:phishtank",
    "twitter"   : "(task.source:twitter OR \
                   task.source:twitter_illegalFawn OR \
                   task.source:twitter_phishingalert)",
    "urlhaus"   : "task.source:urlhaus"
}

extensions = {
    "7z"   : "application/x-7z-compressed",
    "apk"  : "application/java-archive",
    "bat"  : "donotcheck",
    "dll"  : "application/x-dosexec",
    "doc"  : "application/msword",
    "docx" : "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "exe"  : "application/x-dosexec",
    "gz"   : "application/x-gzip",
    "hta"  : "donotcheck",
    "html" : "donotcheck",
    "iso"  : "application/octet-stream",
    "jar"  : "application/java-archive",
    "json" : "donotcheck",
    "lnk"  : "application/octet-stream",
    "ppt"  : "application/vnd.ms-powerpoint",
    "ps1"  : "donotcheck",
    "py"   : "donotcheck",
    "rar"  : "application/x-rar",
    "sh"   : "donotcheck",
    "tar"  : "donotcheck",
    "vb"   : "donotcheck",
    "vbs"  : "donotcheck",
    "xls"  : "application/vnd.ms-excel",
    "xlsx" : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "zip"  : "application/zip"
}
