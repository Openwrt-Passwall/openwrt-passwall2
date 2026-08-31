#!/bin/sh
## Loop update script

. /usr/share/passwall2/utils.sh
LOCK_FILE=${LOCK_PATH}/${CONFIG}_tasks.lock

CFG_UPDATE_INT=0

exec 99>"$LOCK_FILE"
flock -n 99
if [ "$?" != 0 ]; then
	exit 0
fi

while true
do

	if [ "$CFG_UPDATE_INT" -ne 0 ]; then

		restart_week_mode=$(config_n_get @global_delay[0] restart_week_mode)
		restart_interval_mode=$(config_n_get @global_delay[0] restart_interval_mode)
		restart_interval_mode=$(expr "$restart_interval_mode" \* 60)
		if [ -n "$restart_week_mode" ]; then
			[ "$restart_week_mode" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$restart_interval_mode")" -eq 0 ] && { /etc/init.d/$CONFIG restart > /dev/null 2>&1 & }
			}
		fi

		rules_update_week_mode=$(config_n_get @global_rules[0] update_week_mode)
		rules_update_interval_mode=$(config_n_get @global_rules[0] update_interval_mode)
		rules_update_interval_mode=$(expr "$rules_update_interval_mode" \* 60)
		if [ -n "$rules_update_week_mode" ]; then
			[ "$rules_update_week_mode" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$rules_update_interval_mode")" -eq 0 ] && { lua $APP_PATH/rule_update.lua log all cron > /dev/null 2>&1 & }
			}
		fi

		TMP_SUB_PATH=$TMP_PATH/sub_tasks
		mkdir -p $TMP_SUB_PATH
		for item in $(uci show ${CONFIG} | grep "=subscribe_list" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
			sub_update_week_mode=$(config_n_get $item update_week_mode)
			if [ -n "$sub_update_week_mode" ]; then
				remark=$(config_n_get $item remark)
				sub_update_interval_mode=$(config_n_get $item update_interval_mode)
				echo "$item" >> $TMP_SUB_PATH/${sub_update_week_mode}_${sub_update_interval_mode}
			fi
		done

		[ -d "${TMP_SUB_PATH}" ] && {
			for name in $(ls ${TMP_SUB_PATH}); do
				sub_update_week_mode=$(echo $name | awk -F '_' '{print $1}')
				sub_update_interval_mode=$(echo $name | awk -F '_' '{print $2}')
				sub_update_interval_mode=$(expr "$sub_update_interval_mode" \* 60)
				cfgids=$(echo -n $(cat ${TMP_SUB_PATH}/${name}) | sed 's# #,#g')
				[ "$sub_update_week_mode" = "8" ] && {
					[ "$(expr "$CFG_UPDATE_INT" % "$sub_update_interval_mode")" -eq 0 ] && { lua $APP_PATH/subscribe.lua start $cfgids cron > /dev/null 2>&1 & }
				}

			done
			rm -rf $TMP_SUB_PATH
		}

	fi

	CFG_UPDATE_INT=$(expr "$CFG_UPDATE_INT" + 10)

	sleep 600

done 2>/dev/null
