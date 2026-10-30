# HostZit appliance: the setup menu starts when hzadmin signs in on the
# server's own screen (not over SSH). Leave it for a command line; open it
# again with: sudo hostzit-setup
case "$(tty 2>/dev/null)" in
/dev/tty[0-9]*)
    if [ "$(id -un)" = hzadmin ] && [ -z "${HZ_MENU_SHOWN:-}" ]; then
        export HZ_MENU_SHOWN=1
        sudo -n /usr/local/sbin/hostzit-setup
    fi
    ;;
esac
