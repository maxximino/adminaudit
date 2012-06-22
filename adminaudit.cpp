/*
 * adminaudit.cpp
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

#include <stdio.h>
#include <syslog.h>
#include <mysql.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <vector>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <mutex>
#include <map>
#include <list>
#include <boost/thread/shared_mutex.hpp>
#include <sys/stat.h>
#include <unistd.h>
#include "adminaudit.hpp"
static inline const char* checkptr(const char* in) { /* Don't ask me why sometimes the user parameters points to NULL (from the structure received from MySQL) , but I've seen SIGSEGVs for this problem. So check it instead of crashing. */
    if(in==NULL) {
        return empty;
    }
    return in;
}

static int getFacility() {

    string s = string(logfacility);
    std::transform(s.begin(), s.end(), s.begin(), (int(*)(int))std::toupper);
    auto it= m_syslog_facilities.find(s);
    if( it == m_syslog_facilities.end() ) {
        cerr << "Cannot parse syslog facility for audit:" << s <<endl;
        throw InitializationException();
    }
    return it->second;
}
static int getLevel(char* lev) {
    string s = string(lev);
    std::transform(s.begin(), s.end(), s.begin(), (int(*)(int))std::toupper);
    auto it= m_syslog_levels.find(s);
    if( it == m_syslog_levels.end() ) {
        cerr << "Cannot parse syslog level for audit:" << s <<endl;
        throw InitializationException();
    }
    return it->second;
}

static bool isTracked(unsigned long threadid) {
    bool retval = false;
    sm_connections.lock_shared();
    for (auto it = connections.begin(); it!=connections.end(); ++it) {
        if(threadid==it->connectionid) {
            retval=true;
            break;
        }
    }
    sm_connections.unlock_shared();
    return retval;
}

static bool track(const struct mysql_event_connection *ec) {
    trackedConnection newconn;
    newconn.connectionid=ec->thread_id;
    newconn.username=string(checkptr(ec->user));
    newconn.hostname=string(checkptr(ec->host));
    newconn.privileges=string(checkptr(ec->priv_user));
    newconn.proxyuser=string(checkptr(ec->proxy_user));
    newconn.ip = string(checkptr(ec->ip));
    sm_connections.lock();
    connections.push_front(newconn);
    sm_connections.unlock();
}

static trackedConnection untrack(const struct mysql_event_connection *ec) {
    trackedConnection tc;
    sm_connections.lock();
    for (auto it = connections.begin(); it!=connections.end(); ++it) {
        if(ec->thread_id==it->connectionid) {
            tc = trackedConnection(*it);
            connections.erase(it);
            break;
        }
    }
    sm_connections.unlock();
    return tc;
}
static void loadFile() {
    vector<string> ntu;
    string tmp;
    ifstream input(filename);
    if(!input) {
        cerr << "Cannot open MySQL administrators user list file:" << filename <<endl;
        throw InitializationException();
    }
    input >> tmp;
    cerr  << "Mysql-auditing: reloading administrators file." << endl;
    string msg;
    if(default_track) {
        msg= "Not watching connections of user:";
    }
    else {
        msg= "Watching connections of human administrator:";
    }
    while(!input.eof()) {
        cerr  << msg << tmp << endl;
        ntu.push_back(tmp);
        input >> tmp;
    }
    input.close();
    sm_nontrackedusers.lock();
    nontrackedusers = ntu;
    sm_nontrackedusers.unlock();
}
#define TIMEINTERVAL 10
static void checkFileUpToDate() {
    if(!m_checkfile.try_lock()) {
        return;
    }
    if(time(NULL) > (lastchecktime + TIMEINTERVAL)) {
        struct stat buf;
        stat(filename,&buf);
        if(lastmtime != buf.st_mtime) {
            lastmtime=buf.st_mtime;
            loadFile();
        }
        lastchecktime=time(NULL);
    }
    m_checkfile.unlock();
}
static bool shouldBeTracked(const char* user_in) {
    bool retval = default_track;
    const char* user=checkptr(user_in);
    checkFileUpToDate();
    sm_nontrackedusers.lock_shared();
    for (vector<string>::iterator it = nontrackedusers.begin(); it!=nontrackedusers.end(); ++it) {
        if(!(it->compare(user))) {
            retval=!retval;
            break;
        }
    }
    sm_nontrackedusers.unlock_shared();
    return retval;
}
static int adminaudit_plugin_init(void *arg __attribute__((unused)))
{
    int retval=0;
    try {
        openlog("mysql-auditing",LOG_NDELAY,getFacility());
        syslog_conn_level = getLevel(connectionloglevel);
        syslog_query_level = getLevel(queryloglevel);
        checkFileUpToDate();
    }
    catch(InitializationException e) {
        retval=1;
        //How to tell MySQL that this plugin is MANDATORY and should abort startup without brutally calling abort()?
	abort();
    }

    return retval;
}

static int adminaudit_plugin_deinit(void *arg __attribute__((unused)))
{
    return(0);
}

static void adminaudit_notify(MYSQL_THD thd __attribute__((unused)),
                             unsigned int event_class,
                             const void *event)
{
    if (event_class == MYSQL_AUDIT_CONNECTION_CLASS)
    {
        const struct mysql_event_connection *ec=
            (const struct mysql_event_connection *) event;
        switch (ec->event_subclass)
        {
        case MYSQL_AUDIT_CONNECTION_CONNECT:
            if(shouldBeTracked(ec->user)) {
                track(ec);
                syslog(syslog_conn_level,"Connection from user %s from host %s (%s) - inital database %s - status %i - priv %s - proxyuser %s - TID %lu",checkptr(ec->user),checkptr(ec->host),checkptr(ec->ip),checkptr(ec->database),ec->status,checkptr(ec->priv_user),checkptr(ec->proxy_user),ec->thread_id);
            }

            break;
        case MYSQL_AUDIT_CONNECTION_DISCONNECT:
            if(isTracked(ec->thread_id)) {
                trackedConnection c = untrack(ec);
                syslog(syslog_conn_level,"User %s disconnected from host %s (%s) - status %i - priv %s - proxyuser %s - TID %lu",c.username.c_str(),c.hostname.c_str(),c.ip.c_str(),ec->status,c.privileges.c_str(),c.proxyuser.c_str(),ec->thread_id);
            }
            break;
        case MYSQL_AUDIT_CONNECTION_CHANGE_USER:
            if(isTracked(ec->thread_id)) {
                trackedConnection c = untrack(ec);
                syslog(syslog_conn_level,"TID %lu old user %s from host %s (%s) - status %i - priv %s - proxyuser %s",ec->thread_id,c.username.c_str(),c.hostname.c_str(),c.ip.c_str(),ec->status,c.privileges.c_str(),c.proxyuser.c_str());
            }
            if(shouldBeTracked(ec->user)) {
                track(ec);
                syslog(syslog_conn_level,"TID %lu new user %s from host %s (%s) - inital database %s - status %i - priv %s - proxyuser %s",ec->thread_id,checkptr(ec->user),checkptr(ec->host),checkptr(ec->ip),checkptr(ec->database),ec->status,checkptr(ec->priv_user),checkptr(ec->proxy_user));
            }
            break;
        default:
            break;
        }
    }
    if(!logquery) {
        return;
    }
    if (event_class == MYSQL_AUDIT_GENERAL_CLASS)
    {
        const struct mysql_event_general *eg=
            (const struct mysql_event_general *) event;
        switch (eg->event_subclass)
        {
        case MYSQL_AUDIT_GENERAL_LOG:
            break;
        case MYSQL_AUDIT_GENERAL_ERROR:
            break;
        case MYSQL_AUDIT_GENERAL_RESULT:
            break;
        case MYSQL_AUDIT_GENERAL_STATUS:

            if(!isTracked(eg->general_thread_id)) {
                return;
            }
            syslog(syslog_query_level,"General status TID %lu:  %s - %s - %s",eg->general_thread_id,eg->general_user,eg->general_command,eg->general_query);
            break;
        default:
            break;
        }
    }

}
