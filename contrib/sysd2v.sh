#!/bin/sh
# sysd2v v0.3  --  systemd unit to sysvinit script converter
# Copyright (C) 2019  Trek http://www.trek.eu.org/devel/sysd2v
# distributed under the terms of the GNU General Public License 3


nl="
"

# read a systemd unit file and set variables named ini_{section}_{key}
# usage: read_unit filename instance
# filename	service unit configuration file, '-' to read from stdin
# instance	instance name for template units
read_unit()
{
  filename=$1
  instance=$2

  if [ "$filename" != - ]
  then
    inifile_unit_name=${filename##*/}
    inifile_unit_name=${inifile_unit_name%.*}
  fi

  rm_comm='/^[#;]/d'
  concat=':l; /\\$/ { N; s/[[:space:]]*\\\n/ /; tl }'
  subst_inst="s/%[Ii]/$instance/g"
  unit=$(
    cat "$filename" |
    sed "$rm_comm" |
    sed "$concat;$subst_inst"
  )
  section_list=$(
    printf %s "$unit" |
    sed -n 's/^\[\([[:alnum:]]\+\)\].*/\1/p'
  )
  oldifs=$IFS
  IFS=$nl

  for section in $section_list
  do
    get_sect='/^\['"$section"'\]/,/^\[.\+\]/'
    key_list=$(
      printf %s "$unit" |
      sed -n "$get_sect"'s/^\([[:alnum:]]\+\)[[:space:]]*=.*/\1/p' |
      sort -u
    )

    for key in $key_list
    do
      val=$(
        printf %s "$unit" |
        sed -n "$get_sect"'s/^'"$key"'[[:space:]]*=[[:space:]]*\(.*\)/\1/p'
      )
      var=$(
        echo "${section}_$key" |
        tr '[:upper:]' '[:lower:]'
      )
      eval ini_$var=\$val
      [ -n "$debug" ] && echo "ini_$var=$val" >&2
    done
  done

  IFS=$oldifs
}


# read a systemd configuration value and write its prefix to stdout
# usage: get_prefix val
# val		systemd configuration value
get_prefix () { printf %s "$1" | sed -n 's/^\([-@:+!|]*\).*/\1/p'; }


# read a boolean value and returns true or false
# usage: is_true val
# val		boolean value
is_true () { case "$1" in 1|[Oo][Nn]|[Tt]*|[Yy]*) true;; *) false; esac }


# read systemd services list and write LSB facilities to stdout
# usage: get_provides services
# services	list of service units
get_provides ()
{
  lst=
  for dep in $1
  do
    lst=${lst:+$lst }${dep%.service}
  done
  printf %s "$lst"
}


# read systemd units list and write LSB facilities to stdout
# usage: get_depends dependencies [ignores]
# dependencies	list of required units
# ignores	facilities to ignore
get_depends ()
{
  lst=
  for dep in $1
  do
    d=
    case $dep in
      local-fs-pre.target) d=mountkernfs;;
      time-sync.target) d=\$time;;
      systemd-modules-load.service) d=kmod;;
      local-fs.target|network-pre.target) d=\$local_fs;;
      systemd-sysctl.service) d=procps;;
      network.target|network-online.target|systemd-networkd.service)
        d=\$network;;
      nss-lookup.target) d=\$named;;
      rpcbind.target|remote-fs-pre.target) d=\$portmap;;
      remote-fs.target|sysinit.target|basic.target) d=\$remote_fs;;
      syslog.service) d=\$syslog;;
      boot-complete.target|multi-user.target|default.target) d=\$all;;
      *.service) d=${dep%.service};;
      *) echo "WARNING: unsupported target '$dep'" >&2
    esac

    ign=${2:+$2 }$lst
    [ -z "$ign" -o -n "${ign%%*"$d"*}" ] &&
      lst=${lst:+$lst }$d
  done

  printf %s "$lst"
}


# read LSB facilities list and write runlevel to stdout
# usage: get_runlevel facilities
# facilities	list of required facilities
get_runlevel ()
{
  case $1 in
    *\$remote_fs*) echo 2 3 4 5;;
    *) echo S
  esac
}


# write a list of environment files to be executed
# usage: write_env list
# list		files separated by newlines, with prefix (-)
write_env ()
{
  oldifs=$IFS
  IFS=$nl

  for env in $1
  do
    pre=$(get_prefix "$env")
    noerr=

    [ -n "$pre" -a -z "${pre%%*-*}" ] && noerr="[ -r ${env#$pre} ] && "

    printf '%s\n' "$noerr. ${env#$pre}"
  done

  IFS=$oldifs
}


# write an environment variable containing paths
# usage: write_path name prefix list
# name		name of the environment variable
# prefix	path prefix to append directories
# list		paths separated by spaces or newlines
write_path ()
{
  lst=
  for dir in $3
  do
    lst=${lst:+$lst:}$2/$dir
  done

  [ -z "$3" ] || printf '%s=%s\n' $1 $lst
}


# write a list of directories to be created
# usage: write_install prefix list [user [group [mode]]]
# prefix	path prefix to append directories
# list		paths separated by spaces or newlines
# user		user ownership
# group		group ownership
# mode		permission mode
write_install ()
{
  for dir in $2
  do
    printf '  install -d %s%s/%s || return 2\n' \
      "${3:+-o $3 }${4:+-g $4 }${5:+-m $5 }" "$1" "$dir"
  done
}


# write a list of commands applying systemd executable prefixes
# usage: write_commands list [run [runpriv]]
# list		commands separated by newlines, with prefixes (-@:+!)
# run		command line to run each command (nice, chrt, ...)
# runpriv	command line to set privileges (runuser, ...)
write_commands ()
{
  oldifs=$IFS
  IFS=$nl

  for cmd in $1
  do
    pre=$(get_prefix "$cmd")
    beg=$3
    end=' || return 2'

    if [ -n "$pre" ]
    then
      [ -z "${pre%%*-*}" ] && end=
      [ -z "${pre%%*[+!]*}" ] && beg=
      [ -z "${pre%%*[@:]*}" ] &&
        echo "WARNING: unsupported exec prefix '$pre'" >&2
    fi

    printf '  %s\n' "$2$beg${cmd#$pre}$end"
  done

  IFS=$oldifs
}


# read a list of commands separated by newlines and write an override function
# usage: write_function name [commands]
# name		function name (start_cmd, stop_cmd, ...)
# commands	list of commands, read from stdin if omitted
write_function ()
{
  lst=${2-$(cat)}

  [ -n "$lst" ] || return
  [ "$lst" = : ] && printf "do_${1}_override () :\n\n" && return

  end='  true\n'
  [ -z "${lst%%*|| return [0-9]}" -o -z "${lst%%*|| return \$?}" ] && end=
  printf "do_${1}_override ()\n{\n%s\n$end}\n\n" "$lst"
}


# write an init-d-script file starting from the ini_* vars (see read_unit)
# usage: write_init servicename instance
# servicename	name of the service provided
# instance	instance name for template units
write_init ()
{
  name=$1
  instance=$2

  if [ "${name%@}" != "$name" ]
  then
    name=$name$instance
  fi

  daemon_pre=$(get_prefix "$ini_service_execstart")
  daemon=${ini_service_execstart#$daemon_pre}

  if [ "${daemon%%[[:space:]]*}" != "$daemon" ]
  then
    daemon_args=${daemon#*[[:space:]]}
    daemon=${daemon%%[[:space:]]*}
  fi

  pidfile=$ini_service_pidfile

  if [ -n "$ini_service_user" ]
  then
    start_args="--user $ini_service_user"
    [ -n "$daemon_pre" -a -z "${daemon_pre%%*[+!]*}" ] ||
      start_args="$start_args --chuid $ini_service_user"
    stop_args="--user $ini_service_user"
    runprivstart="runuser -u $ini_service_user -- "
    is_true "$ini_service_permissionsstartonly" || runpriv=$runprivstart
  fi

  cls=$ini_service_ioschedulingclass
  pri=$ini_service_ioschedulingpriority
  [ -n "$cls$pri" ] &&
    start_args="$start_args --iosched ${cls:-best-effort}${pri:+:$pri}" &&
    run="ionice ${cls:+-c $cls }${pri:+-n $pri }"

  pol=$ini_service_cpuschedulingpolicy
  pri=$ini_service_cpuschedulingpriority
  [ -n "$pol$pri" ] &&
    start_args="$start_args --procsched ${pol:-other}${pri:+:$pri}" &&
    run="${run}chrt ${pol:+--$pol }${pri:-0} "

  [ -n "$ini_service_nice" ] &&
    start_args="$start_args --nicelevel $ini_service_nice" &&
    run="${run}nice -n $ini_service_nice "

  pre=$(get_prefix "$ini_service_workingdirectory")
  workdir=${ini_service_workingdirectory#$pre}
  [ "$workdir" = '~' ] && workdir=\~$ini_service_user
  [ -n "$workdir" ] &&
    start_args="$start_args --chdir $workdir" &&
    chdir="${pre}cd $workdir"

  if [ -z "${service_type:=$ini_service_type}" ]
  then
    if [ -n "$ini_service_busname" ]
    then
      service_type=dbus
    elif [ -n "$ini_service_execstart" ]
    then
      service_type=simple
    else
      service_type=oneshot
    fi
  fi

  if [ "$service_type" != forking ]
  then
    start_args="$start_args --background"
    [ -z "$pidfile" -a "$ini_service_killmode" != none ] &&
      start_args="$start_args --make-pidfile" &&
      pidfile="/var/run/$name-sysd2v.pid"
  fi

  if [ "$service_type" = notify ]
  then
    start_args="$start_args --notify-await"
    timeout=${ini_service_timeoutstartsec:-$ini_service_timeoutsec}
    timeout=${timeout%s}
    [ -n "${timeout#60}" ] &&
      start_args="$start_args --notify-timeout $timeout"
    [ -n "$timeout" -a -z "${timeout%%*[^0-9]*}" ] &&
      echo "WARNING: unsupported timeout '$timeout'" >&2
  elif [ "$service_type" = dbus ]
  then
    : TODO
  fi

  signal=${ini_service_killsignal#SIG}
  timeout=${ini_service_timeoutstopsec:-$ini_service_timeoutsec}
  timeout=${timeout%s}
  [ -n "${signal#TERM}" -o -n "${timeout#90}" ] &&
    stop_args="$stop_args --retry=${signal:-TERM}/${timeout:-90}/KILL/5"

  limitnofile=$ini_service_limitnofile
  [ "$limitnofile" = infinity ] && limitnofile=unlimited

  need_install=$ini_service_runtimedirectory
  need_install=$need_install$ini_service_statedirectory
  need_install=$need_install$ini_service_cachedirectory
  need_install=$need_install$ini_service_logsdirectory
  need_install=$need_install$ini_service_configurationdirectory

  need_do_start=$ini_service_execstartpre$ini_service_execstartpost
  need_do_start=$need_do_start$need_install

  execstop=$ini_service_execstop

  if [ "$service_type" != oneshot ]
  then
    [ "$pidfile" = "/var/run/${daemon##*/}.pid" ] && unset pidfile
    [ "$name" = "${daemon##*/}" ] && unset name

    [ -n "$daemon_args" -a -z "${daemon_args%%*[\"\\]*}" ] &&
      echo "WARNING: DAEMON_ARGS needs to be escaped" >&2
    errcheck=' || return $?'

    if [ -n "$daemon_pre" ]
    then
      [ -z "${daemon_pre%%*-*}" ] && errcheck=
      [ -z "${daemon_pre%%*[@:]*}" ] &&
        echo "WARNING: unsupported exec prefix '$daemon_pre'" >&2
    fi

    # TODO: test if already running before start (pretest="+do_status_cmd")
    [ -n "$need_do_start" -o -z "$errcheck" ] &&
      execstart="-+do_start_cmd$errcheck"

    errcheck=' || return $?'
    [ -n "$execstop" ] && errcheck=
    [ -n "$execstop$ini_service_execstoppost" -a \
      "$ini_service_killmode" != none ] &&
      killstop="-do_stop_cmd$errcheck"

    [ -n "$timeout" -a -z "${timeout%%*[^0-9]*}" ] &&
      echo "WARNING: unsupported timeout '$timeout'" >&2
  else
    daemon=none
    pidfile=none
    : ${name:=SERVICE_NAME}
    unset daemon_args start_args stop_args
    execstart=$ini_service_execstart
    runstart=$run
  fi

  need_do_start=$need_do_start$execstart
  start_args=${start_args# }
  stop_args=${stop_args# }

  aliases=$(get_provides "$ini_install_alias")

  [ -z "$ini_unit_defaultdependencies" ] ||
    is_true "$ini_unit_defaultdependencies" &&
    defdep=sysinit.target

  req_start=$(get_depends "$ini_unit_requires $defdep")
  should_start=$(get_depends "$ini_unit_wants $ini_unit_after" "$req_start")

  default_start=$(get_runlevel "$req_start $should_start")
  [ "$default_start" = S ] && default_stop='0 6' || default_stop='0 1 6'
  [ -z "$execstop$ini_service_execstoppost" ] &&
    [ "$service_type" = oneshot -o "$ini_service_killmode" = none ] &&
    default_stop=

  [ "$default_start" = S ] && ignore=\$remote_fs
  start_before=$(get_depends "$ini_unit_requiredby $ini_install_wantedby
    $ini_unit_before" "$req_start $should_start \$all $ignore")

  cat <<EOF
#!/bin/sh
# Generated by sysd2v v0.3  --  http://www.trek.eu.org/devel/sysd2v
# kFreeBSD do not accept scripts as interpreters, using #!/bin/sh and sourcing.
if [ true != "\$INIT_D_SCRIPT_SOURCED" ] ; then
    set "\$0" "\$@"; INIT_D_SCRIPT_SOURCED=true . /lib/init/init-d-script
fi
### BEGIN INIT INFO
# Provides:       ${name:-${daemon##*/}}${aliases:+ $aliases}
# Required-Start: $req_start
# Required-Stop:  ${default_stop:+$req_start}
${should_start:+# Should-Start:   $should_start
${default_stop:+# Should-Stop:    $should_start
}}${start_before:+# X-Start-Before: $start_before
${default_stop:+# X-Stop-After:   $start_before
}}# Default-Start:  $default_start
# Default-Stop:   $default_stop
# Description:    ${ini_unit_description:-SERVICE_DESCRIPTION}
### END INIT INFO
EOF

  if [ -n "$ini_service_environment$ini_service_environmentfile$need_install" ]
  then
    echo set -a
    write_path RUNTIME_DIRECTORY /run "$ini_service_runtimedirectory"
    write_path STATE_DIRECTORY /var/lib "$ini_service_statedirectory"
    write_path CACHE_DIRECTORY /var/cache "$ini_service_cachedirectory"
    write_path LOGS_DIRECTORY /var/log "$ini_service_logsdirectory"
    write_path CONFIGURATION_DIRECTORY /etc \
      "$ini_service_configurationdirectory"
    printf '%s' "${ini_service_environment:+$ini_service_environment$nl}"
    write_env "$ini_service_environmentfile"
    printf 'set +a\n\n'
  fi

  cat <<EOF
${name:+DESC=\"$name\"
}DAEMON=$daemon
${daemon_args:+DAEMON_ARGS=\"$daemon_args\"
}${pidfile:+PIDFILE=$pidfile
}${start_args:+START_ARGS=\"$start_args\"
}${stop_args:+STOP_ARGS=\"$stop_args\"
}${limitnofile:+ulimit -n $limitnofile
}${ini_service_umask:+umask $ini_service_umask
}
EOF

  if [ -n "$need_do_start" ]
  then
    {
      write_install /run "$ini_service_runtimedirectory" \
        "$ini_service_user" "$ini_service_group" \
        "$ini_service_runtimedirectorymode"
      write_install /var/lib "$ini_service_statedirectory" \
        "$ini_service_user" "$ini_service_group" \
        "$ini_service_statedirectorymode"
      write_install /var/cache "$ini_service_cachedirectory" \
        "$ini_service_user" "$ini_service_group" \
        "$ini_service_cachedirectorymode"
      write_install /var/log "$ini_service_logsdirectory" \
        "$ini_service_user" "$ini_service_group" \
        "$ini_service_logsdirectorymode"
      write_install /etc "$ini_service_configurationdirectory" '' '' \
        "$ini_service_configurationdirectorymode"
      write_commands "$chdir"
      write_commands "$ini_service_execstartpre" "$run" "$runpriv"
      write_commands "$execstart" "$runstart" "$runprivstart"
      write_commands "$ini_service_execstartpost" "$run" "$runpriv"
    } | write_function start_cmd
  else
    [ "$service_type" = oneshot ] && write_function start :
  fi

  if [ -n "$execstop$ini_service_execstoppost" ]
  then
    {
      write_commands "$chdir"
      write_commands "$execstop" "$run" "$runpriv"
      write_commands "$killstop"
      write_commands "$ini_service_execstoppost" "$run" "$runpriv"
    } | write_function stop_cmd
  else
    [ "$service_type" = oneshot -o "$ini_service_killmode" = none ] &&
      write_function stop :
  fi

  if [ "$ini_service_execreload" = '/bin/kill -HUP $MAINPID' -a \
       -z "$run$runpriv" ]
  then
    printf 'alias do_reload=do_reload_sigusr1\n\n'
  elif [ -n "$ini_service_execreload" ]
  then
    {
      write_commands "$chdir"
      write_commands "$ini_service_execreload" "$run" "$runpriv"
    } | write_function reload_cmd

    cat <<"EOF"
do_reload ()
{
  log_daemon_msg "Reloading $DESC configuration files" "$NAME"
  MAINPID=$(cat $PIDFILE)
  do_reload_cmd_override
  log_end_msg $?
}
EOF
  fi

  [ "$service_type" = oneshot ] && write_function status :
}


# parse command line
while getopts di:n: opt
do
    case $opt in
      d) debug=1;;
      i) instance=$OPTARG;;
      n) name=$OPTARG;;
      ?) printf "Usage: %s [-d] [-i instance] [-n servicename] [filename]\n" \
           "$0"
         exit 2;;
    esac
done

: ${instance=INSTANCE_NAME}
shift $(($OPTIND - 1))


# convert unit file
read_unit "${1:--}" "$instance"
write_init "${name-$inifile_unit_name}" "$instance"

