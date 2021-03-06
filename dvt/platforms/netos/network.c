/*
 * Copyright (c) 2013 Digi International Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */
#include <stdio.h>
#include <string.h>

#include "sockapi.h"
#include "naerrno.h"

#include "connector_api.h"
#include "platform.h"
#include "nareset.h"

static int app_dns_resolve_name(char const * const domain_name, in_addr_t * const ip_addr)
{
    int ret = -1;
    struct addrinfo *res_list;
    struct addrinfo *res;

    if ((domain_name == NULL) || (ip_addr == NULL))
    {
        goto done;
    }

    {
        struct addrinfo hint = {0};
        int error;

        hint.ai_socktype = SOCK_STREAM;
        hint.ai_family   = AF_INET;
        error = getaddrinfo(domain_name, NULL, &hint, &res_list);
        if (error != 0)
        {
            APP_DEBUG("dns_resolve_name: DNS resolution failed for [%s]\n", domain_name);
            goto done;
        }
    }

    /* loop over all returned results and look for a IPv4 address */
    for (res = res_list; res; res = res->ai_next)
    {
        if (res->ai_family == PF_INET)
        {
            struct in_addr const ipv4_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;

            *ip_addr = ipv4_addr.s_addr;
            APP_DEBUG("dns_resolve_name: ip address = [%s]\n", inet_ntoa(ipv4_addr));
            ret = 0;
            break;
        }
    }

    freeaddrinfo(res_list);

done:
    return ret;
}

static connector_callback_status_t app_network_connect(char const * const host_name, size_t const length, connector_network_handle_t ** network_handle)
{
    connector_callback_status_t rc = connector_callback_abort;
    static int fd = -1;

    if (fd == -1)
    {
        in_addr_t ip_addr;

        {
            char server_name[64];

            if (length >= ARRAY_SIZE(server_name))
            {
                APP_DEBUG("app_connect_to_server: server name length [%" PRIsize "]\n", length);
                goto done;
            }

            memcpy(server_name, host_name, length);
            server_name[length] = '\0';

            /*
             * Check if it's a dotted-notation IP address, if it's a domain name,
             * attempt to resolve it.
             */
            ip_addr = inet_addr(server_name);
            if (ip_addr == INADDR_NONE)
            {
                if (app_dns_resolve_name(server_name, &ip_addr) != 0)
                {
                    APP_DEBUG("network_connect: Can't resolve DNS for %s\n", server_name);
                    goto done;
                }
            }
        }

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0)
        {
            int enabled = 1;

            if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&enabled, sizeof(enabled)) < 0)
            {
                perror("open_socket: setsockopt SO_KEEPALIVE failed");
            }

            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&enabled, sizeof(enabled)) < 0)
            {
                perror("open_socket: setsockopt TCP_NODELAY failed");
            }

            if (setsockopt(fd, SOL_SOCKET, SO_NONBLOCK, (char*)&enabled, sizeof(enabled)) < 0)
            {
                perror("open_socket: setsockopt SO_NONBLOCK failed");
            }
        }
        else
        {
            perror("Could not open socket");
            goto done;
        }

        {
            struct sockaddr_in sin = {0};

            memset((char *)&sin, 0, sizeof(sin));
            memcpy(&sin.sin_addr, &ip_addr, sizeof sin.sin_addr);
            sin.sin_port   = htons(CONNECTOR_PORT);
            sin.sin_family = AF_INET;

            if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) < 0)
            {
                switch (getErrno())
                {
                case EAGAIN:
                case EINPROGRESS:
                    break;
                default:
                    perror("network_connect: connect() failed");
                    goto done;
                }
            }
        }
    }


    {
        struct timeval timeout = {0};
        fd_set read_set;
        fd_set write_set;

        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        write_set = read_set;
        timeout.tv_sec = 30;

        if (select(fd+1, &read_set, &write_set, NULL, &timeout) <= 0)
        {
            goto done;
        }

        /* Check whether the socket is now writable (connection succeeded). */
        if (FD_ISSET(fd, &write_set))
        {
            /* We expect "socket writable" when the connection succeeds. */
            /* If we also got a "socket readable" we have an error. */
            if (FD_ISSET(fd, &read_set))
            {
                APP_DEBUG("network_connect: error to connect to %.*s server\n", (int)length, host_name);
                goto done;
            }
            *network_handle = &fd;
            rc = connector_callback_continue;
            APP_DEBUG("network_connect: connected to [%.*s] server\n", (int)length, host_name);
        }
    }

done:
    if ((rc == connector_callback_abort) && (fd >= 0))
    {
        closesocket(fd);
        fd = -1;
    }

    return rc;
}

/*
 * Sends data to the iDigi server, this routine must not block.  If it encounters
 * EAGAIN  error, return connector_callback_busy and Cloud Connector will ignore the
 * sent_length and continue calling this function.
 */
static connector_callback_status_t app_network_send(connector_write_request_t const * const write_data,
                                            size_t * const sent_length)
{
    connector_callback_status_t rc = connector_callback_continue;

    int const bytes_sent =  send(*write_data->network_handle, (char *)write_data->buffer,
                 write_data->length, 0);
    if (bytes_sent < 0) 
    {
        if (getErrno() == EWOULDBLOCK)
        {
            rc = connector_callback_busy;
        }
        else
        {
            rc = connector_callback_abort;
            perror("network_send: send() failed");
        }
    }
    *sent_length = bytes_sent;

    return rc;
}

/*
 * This routine reads a specified number of bytes from the iDigi server.  This 
 * function must not block. If it encounters EAGAIN  error, return
 * connector_callback_busy and Cloud Connector will ignore the read_data and read_length
 * and continue calling this function.
 */
static connector_callback_status_t app_network_receive(connector_read_request_t const * const read_data, size_t * const read_length)
{
    connector_callback_status_t rc = connector_callback_continue;
    struct timeval timeout = {0};
    fd_set read_set;
    int ccode;

    *read_length = 0;

    FD_ZERO(&read_set);
    FD_SET(*read_data->network_handle, &read_set);

    timeout.tv_sec = read_data->timeout;
    /* Blocking point for Cloud Connector */
    ccode = select((*read_data->network_handle)+1, &read_set, NULL, NULL, &timeout);
    if (ccode < 0)
    {
        goto done;
    }

    if (ccode == 0)
    {
        rc = connector_callback_busy;
        goto done;
    }
    ccode = recv(*read_data->network_handle, (char *)read_data->buffer, (int)read_data->length, 0);

    if (ccode == 0)
    {
        /* EOF on input: the connection was closed. */
        APP_DEBUG("network_receive: EOF on socket\r\n");
        errno = ECONNRESET;
        rc = connector_callback_abort;
    }
    else if (ccode < 0)
    {
        int const err = getErrno();
        /* An error of some sort occurred: handle it appropriately. */
        if (err == EAGAIN)
        {
            rc = connector_callback_busy;
        }
        else
        {
            perror("network_receive: recv() failed");
            /* if not timeout (no data) return an error */
            rc = connector_callback_abort;
        }
    }

    *read_length = (size_t)ccode;
done:

    return rc;
}

static connector_callback_status_t app_network_close(connector_network_handle_t * const fd)
{
    connector_callback_status_t status = connector_callback_continue;
    struct linger ling_opt;

    ling_opt.l_onoff = 1;
    ling_opt.l_linger = 1;

    if (setsockopt(*fd, SOL_SOCKET, SO_LINGER, (char*)&ling_opt, sizeof(ling_opt) ) < 0)
    {
        perror("network close: setsockopt fails: ");
        if (getErrno() == EAGAIN)
        {
            status = connector_callback_busy;
        }
    }
    if (closesocket(*fd) < 0)
    {
        perror("network_close: close() failed");
    }

    *fd = -1;

    return status;
}

static connector_callback_status_t app_server_disconnected(void)
{

    APP_DEBUG("Disconnected from server\n");
    /* if connector_run or connector_step is called again,
     * it will reconnect to the iDigi Device Cloud.
     */
    return connector_callback_continue;
}

static connector_callback_status_t app_server_reboot(void)
{

    APP_DEBUG("Reboot from server\n");
    /* should not return from rebooting the system */
    return connector_callback_continue;
}


/*
 *  Callback routine to handle all networking related calls.
 */
connector_callback_status_t app_network_handler(connector_network_request_t const request,
                                            void const * const request_data, size_t const request_length,
                                            void * response_data, size_t * const response_length)
{
    connector_callback_status_t status;

    UNUSED_ARGUMENT(request_length);

    switch (request)
    {
    case connector_network_open:
        status = app_network_connect(request_data, request_length, response_data);
        *response_length = sizeof(connector_network_handle_t);
        break;

    case connector_network_send:
        status = app_network_send(request_data, response_data);
        break;

    case connector_network_receive:
        status = app_network_receive(request_data, response_data);
        break;

    case connector_network_close:
        status = app_network_close((connector_network_handle_t * const)request_data);
        break;

    case connector_network_disconnected:
       status = app_server_disconnected();
       break;

    case connector_network_reboot:
        status = app_server_reboot();
        break;

    default:
        APP_DEBUG("app_network_handler: unrecognized callback request [%d]\n", request);
        status = connector_callback_unrecognized;
        break;

    }

    return status;
}

