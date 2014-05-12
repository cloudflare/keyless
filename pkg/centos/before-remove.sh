if [ $1 -eq 0 ]; then
  /sbin/service keyless stop >/dev/null 2>&1 || true
  /sbin/chkconfig --del keyless
  if getent passwd keyless >/dev/null ; then
    userdel keyless
  fi

  if getent group keyless >/dev/null ; then
    groupdel keyless
  fi
fi
