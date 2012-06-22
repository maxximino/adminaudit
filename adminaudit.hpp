/*
 * adminaudit.hpp
 * 
 * Copyright (c) 2012, Massimo Maggi. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */

#include <syslog.h>
#include <mysql.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <vector>
#include <map>
#include <mutex>
#include <list>
#include <boost/thread/shared_mutex.hpp>

#define TIMEINTERVAL 10

using namespace std;
class trackedConnection {
public:
    unsigned long connectionid;
    string username;
    string hostname;
    string privileges;
    string proxyuser;
    string ip;
};

static boost::shared_mutex sm_nontrackedusers;
static vector<string> nontrackedusers;
static boost::shared_mutex sm_connections;
static list<trackedConnection> connections;
char logquery;
char default_track;
char* filename;
char* connectionloglevel;
char* queryloglevel;
char* logfacility;
static int syslog_conn_level=0;
static int syslog_query_level=0;
static time_t lastchecktime = 0;
static time_t lastmtime = 0;
static mutex m_checkfile;

static map<string,int> m_syslog_levels = {
    {"EMERG",LOG_EMERG},
    {"ALERT",LOG_ALERT},
    {"CRIT",LOG_CRIT},
    {"ERR",LOG_ERR},
    {"WARNING",LOG_WARNING},
    {"NOTICE",LOG_NOTICE},
    {"INFO",LOG_INFO},
    {"DEBUG",LOG_DEBUG},
};
static map<string,int> m_syslog_facilities = {
    {"AUTH",LOG_AUTH},
    {"AUTHPRIV",LOG_AUTHPRIV},
    {"CRON",LOG_CRON},
    {"DAEMON",LOG_DAEMON},
    {"FTP",LOG_FTP},
    {"KERN",LOG_KERN},
    {"LPR",LOG_LPR},
    {"MAIL",LOG_MAIL},
    {"NEWS",LOG_NEWS},
    {"SYSLOG",LOG_SYSLOG},
    {"USER",LOG_USER},
    {"UUCP",LOG_UUCP},
    {"LOCAL0",LOG_LOCAL0},
    {"LOCAL1",LOG_LOCAL1},
    {"LOCAL2",LOG_LOCAL2},
    {"LOCAL3",LOG_LOCAL3},
    {"LOCAL4",LOG_LOCAL4},
    {"LOCAL5",LOG_LOCAL5},
    {"LOCAL6",LOG_LOCAL6},
    {"LOCAL7",LOG_LOCAL7},
};

class InitializationException {};

const char empty[] = "";
static inline const char* checkptr(const char* in);

static int getFacility();
static int getLevel(char* lev);

static bool isTracked(unsigned long threadid);

static bool track(const struct mysql_event_connection *ec);
static trackedConnection untrack(const struct mysql_event_connection *ec);
static void loadFile();

static void checkFileUpToDate();
static bool shouldBeTracked(const char* user);
static int adminaudit_plugin_init(void *arg __attribute__((unused)));

static int adminaudit_plugin_deinit(void *arg __attribute__((unused)));

static void adminaudit_notify(MYSQL_THD thd __attribute__((unused)),
                             unsigned int event_class,
                             const void *event);

static struct st_mysql_audit adminaudit_descriptor=
{
    MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
    NULL,                                             /* release_thd function */
    adminaudit_notify,                                /* notify function      */
    { (unsigned long) MYSQL_AUDIT_CONNECTION_CLASSMASK | MYSQL_AUDIT_GENERAL_CLASSMASK} /* class mask           */
};


static MYSQL_SYSVAR_STR(filename, filename, PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY, "Path to administrators list", NULL,NULL,"");
static MYSQL_SYSVAR_STR(connectionloglevel, connectionloglevel, PLUGIN_VAR_OPCMDARG | PLUGIN_VAR_READONLY, "Syslog level for connection-related AUDIT messages", NULL,NULL,"NOTICE");
static MYSQL_SYSVAR_STR(queryloglevel, queryloglevel, PLUGIN_VAR_OPCMDARG | PLUGIN_VAR_READONLY, "Syslog level for query-related AUDIT messages", NULL,NULL,"INFO");
static MYSQL_SYSVAR_STR(logfacility, logfacility, PLUGIN_VAR_OPCMDARG | PLUGIN_VAR_READONLY, "Syslog facility for AUDIT messages", NULL,NULL,"AUTHPRIV");
static MYSQL_SYSVAR_BOOL(logquery, logquery,
                         PLUGIN_VAR_OPCMDARG | PLUGIN_VAR_READONLY,
                         "Log query by admins ",
                         NULL,				   // check
                         NULL, // update
                         0);
static MYSQL_SYSVAR_BOOL(default_track, default_track,
                         PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
                         "TRUE=File contains a list of users which should not be tracked, FALSE=File contains the list of the only users that should be tracked.",
                         NULL,				   // check
                         NULL, // update
                         1);

static struct st_mysql_sys_var* adminaudit_system_vars[]= {
    MYSQL_SYSVAR(filename),
    MYSQL_SYSVAR(connectionloglevel),
    MYSQL_SYSVAR(queryloglevel),
    MYSQL_SYSVAR(logfacility),
    MYSQL_SYSVAR(logquery),
    MYSQL_SYSVAR(default_track),
    NULL,
};

mysql_declare_plugin(adminaudit)
{
    MYSQL_AUDIT_PLUGIN,         /* type                            */
    &adminaudit_descriptor,     /* descriptor                      */
    "adminaudit",               /* name                            */
    "Massimo Maggi",              /* author                          */
    "Audit administrator's actions",        /* description                     */
    PLUGIN_LICENSE_GPL,
    adminaudit_plugin_init,     /* init function (when loaded)     */
    adminaudit_plugin_deinit,   /* deinit function (when unloaded) */
    0x0001,                     /* version                         */
    NULL,              /* status variables                */
    adminaudit_system_vars,                       /* system variables                */
    NULL,
    0,
}
mysql_declare_plugin_end;

