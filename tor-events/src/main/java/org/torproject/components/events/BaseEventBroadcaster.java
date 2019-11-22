/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED,
INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache 2 License for the specific language governing permissions and limitations under the License.
*/

package org.torproject.components.events;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class BaseEventBroadcaster implements EventBroadcaster {

    protected static final Logger LOG = LoggerFactory.getLogger(BaseEventBroadcaster.class);
    protected final AtomicBoolean debugLogsEnabled;
    protected final Status mStatus;

    public BaseEventBroadcaster(AtomicBoolean debugLogsEnabled) {
        this.debugLogsEnabled = debugLogsEnabled == null ? new AtomicBoolean(false) : debugLogsEnabled;
        mStatus = new Status(this);
    }

    @Override
    public void broadcastDebug(String msg) {
        if (debugLogsEnabled.get()) {
            LOG.debug(msg);
            broadcastLogMessage(msg);
        }
    }

    @Override
    public void broadcastException(String msg, Exception e) {
        if (debugLogsEnabled.get()) {
            LOG.error(msg, e);
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            broadcastLogMessage(msg + '\n' + sw.toString());
        } else {
            broadcastLogMessage(msg);
        }
    }

    @Override
    public void broadcastNotice(String msg) {
        if (msg != null && !msg.isEmpty()) {
            if (debugLogsEnabled.get()) {
                LOG.debug(msg);
            }
            broadcastLogMessage(msg);
        }
    }

    @Override
    public Status getStatus() {
        return mStatus;
    }
}
