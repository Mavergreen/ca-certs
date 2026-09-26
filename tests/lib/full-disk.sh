# platform: macOS-only -- a file-size limit of 0 stands in for a full disk; this 10.9 kernel gives a
#           limit set by `ulimit -f` only to the first process forked after it, so the tool is that
#           process, and SIGXFSZ is ignored so its write fails (EFBIG) the way ENOSPC would
#   usage: PATH="$R/tests/full-disk:$PATH" FULL_DISK_ON=TEXT ...
#          The body of tests/full-disk/grep and tests/full-disk/sed. A call whose arguments contain
#          TEXT and name the receipt runs the real tool with no room to write a file, as on a full
#          disk: its writes to a file fail, while output to a pipe or terminal and every other call
#          are untouched. 10.9's grep still exits 0 then, having written nothing; its sed exits 1.
case "$*" in
  *"${FULL_DISK_ON:?}"*receipt*)
    trap '' XFSZ
    ulimit -f 0
    "${FULL_DISK_TOOL:?}" "$@"
    exit $?
    ;;
esac
exec "${FULL_DISK_TOOL:?}" "$@"
