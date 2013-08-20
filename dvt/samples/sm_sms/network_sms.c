/*
 * Copyright (c) 2013 Digi International Inc.,
 * All rights not expressly granted are reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */
/**
 * @file
 *  @brief Rountines which implement Cloud Connector network interface for
 *  @ref CONNECTOR_TRANSPORT_SMS.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "connector_api.h"
#include "platform.h"
#include "network_dns.h"

#if defined CONNECTOR_TRANSPORT_SMS

#define GW_PORT		9999
#define GW_IP		"10.101.1.121"

/* Global structure of connected interface */
static struct sockaddr_in interface_addr;

static int app_sms_create_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd >= 0)
    {
        int enabled = 1;

        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) < 0)
        {
            APP_DEBUG("open_socket: setsockopt SO_KEEPALIVE failed, errno %d\n", errno);
        }

        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) < 0)
        {
            APP_DEBUG("open_socket: setsockopt TCP_NODELAY failed, errno %d\n", errno);
        }

        if (ioctl(fd, FIONBIO, &enabled) < 0)
        {
            APP_DEBUG("ioctl: FIONBIO failed, errno %d\n", errno);
            close(fd);
            fd = -1;
        }
    }
    else
    {
        APP_DEBUG("Could not open sms socket, errno %d\n", errno);
    }

    return fd;
}

static connector_callback_status_t app_sms_connect(int const fd, in_addr_t const ip_addr)
{

    struct sockaddr_in sin = {0};
    connector_callback_status_t status = connector_callback_continue;

    memcpy(&sin.sin_addr, &ip_addr, sizeof sin.sin_addr);
    sin.sin_port   = htons(GW_PORT);
    sin.sin_family = AF_INET;

    APP_DEBUG("app_sms_connect: fd %d\n", fd);


    if (connect(fd, &sin, sizeof(sin)) < 0)
    {
        int const err = errno;
        switch (err)
        {
        case EINTR:
        case EAGAIN:
        case EINPROGRESS:
            status = connector_callback_busy;
            break;

        default:
            APP_DEBUG("app_sms_connect: connect() failed, fd %d, errno %d\n", fd, err);
            status = connector_callback_error;
        }
    }

    return status;
}

static connector_callback_status_t app_is_sms_connect_complete(int const fd)
{
    connector_callback_status_t status = connector_callback_busy;
    struct timeval timeout = {0};
    fd_set read_set, write_set;
    int rc;

    FD_ZERO(&read_set);
    FD_SET(fd, &read_set);
    write_set = read_set;

    rc = select(fd+1, &read_set, &write_set, NULL, &timeout);
    if (rc < 0)
    {
        if (errno != EINTR) {
            APP_DEBUG("app_is_sms_connect_complete: select on fd %d returned %d, errno %d\n", fd, rc, errno);
            status = connector_callback_error;
        }
    }
    else
    /* Check whether the socket is now writable (connection succeeded). */
    if (rc > 0 && FD_ISSET(fd, &write_set))
    {
        /* We expect "socket writable" when the connection succeeds. */
        /* If we also got a "socket readable" we have an error. */
        if (FD_ISSET(fd, &read_set))
        {
            APP_DEBUG("app_is_sms_connect_complete: FD_ISSET for read, fd %d\n", fd);
            status = connector_callback_error;

        }
        else
        {
            status = connector_callback_continue;
        }
    }
    return status;
}

connector_callback_status_t config_server_phone_number(int const fd, const char * device_cloud_phone)
{
	connector_callback_status_t status;
	static char const phone_number_prefix[] = "phone-number=";
	char *str_to_send = NULL;
	int ccode;
		
	if (strlen(device_cloud_phone) == 0)
	{
		APP_DEBUG("config_server_phone_number: device_cloud_phone not yet configured\n");
		return connector_callback_error;
	}
	
	str_to_send = malloc(sizeof(phone_number_prefix)+strlen(device_cloud_phone));
	
	if (str_to_send == NULL)
	{
		APP_DEBUG("config_server_phone_number: malloc failed\n");
		return connector_callback_error;
	}
	
	strcpy(str_to_send,phone_number_prefix);
		
	strcat(str_to_send, device_cloud_phone);
	            
	APP_DEBUG("config_server_phone_number: %s\n", str_to_send);
	
	ccode = write(fd, str_to_send, strlen(str_to_send));
    if (ccode >= 0)
    	status = connector_callback_continue;
    else
    	status = connector_callback_error;
    
    free (str_to_send);

    usleep(1000000);	// Let the proxy digest previous command
    
#ifdef CONNECTOR_TRANSPORT_SMS_SHARED_CODE
	#error "We'll make a fake sms_proxy_service_id.py to test shared codes"
  
	{
		static char const service_id_prefix[] = "service-id=";
	    strcpy(str_to_send,service_id_prefix);
	    
		strcat(str_to_send, "idgp");
		
		ccode = write(fd, str_to_send, strlen(str_to_send));
	    if (ccode >= 0)
	    	status = connector_callback_continue;
	    else
	    	status = connector_callback_error;
	}
	usleep(1000000);	// Let the proxy digest previous command
#endif
    
	return(status);
}

/**
 * @brief   Open a network to communicate Device Cloud
 *
 * @param data @ref connector_network_open_t
 *  <ul>
 *   <li><b><i>device_cloud_url</i></b> - FQDN of Device Cloud </li>
 *   <li><b><i>handle</i></b> - This is filled in with the value
 *   of a network handle, passed to subsequent networking calls,
 *   @ref connector_network_handle_t "connector_network_handle_t"
 *      is defined in public\include\connector_types.h.
 *  </li>
 * </ul>
 *
 * @retval connector_callback_continue	The routine has successfully opened a socket and resolved Device Cloud's name.
 * @retval connector_callback_busy 		The routine will be called again to complete open.
 * @retval connector_callback_error     The operation failed, Cloud Connector
 *                                  will exit @ref connector_run "connector_run()" or @ref connector_step "connector_step()".
 * @retval connector_callback_abort     The application aborts Cloud Connector.
 *
 * @see @ref open "Network API callback Open"
 */
static connector_callback_status_t app_network_sms_open(connector_network_open_t * const data)
{
#define APP_CONNECT_TIMEOUT 30

    static unsigned long connect_time;
    static int fd = -1;
    socklen_t interface_addr_len;

    connector_callback_status_t status = connector_callback_error;
    data->handle = &fd;

    if (fd == -1)
    {
        in_addr_t ip_addr;

        status = app_dns_resolve(connector_class_id_network_sms, GW_IP, &ip_addr);
        if (status != connector_callback_continue)
        {
            APP_DEBUG("app_network_sms_open: Can't resolve DNS for %s\n", GW_IP);
            goto done;
        }

        fd = app_sms_create_socket();
        if (fd == -1)
        {
            status = connector_callback_error;
            goto done;
        }

        app_os_get_system_time(&connect_time);
        status = app_sms_connect(fd, ip_addr);
        if (status != connector_callback_continue)
            goto error;
    }

    /* Get socket info of connected interface */
    interface_addr_len = sizeof(interface_addr);
    if (getsockname(fd, &interface_addr, &interface_addr_len))
    {
        APP_DEBUG("network_connect: getsockname error, errno %d\n", errno);
        goto done;
    }

    status = app_is_sms_connect_complete(fd);
    if (status == connector_callback_continue)
    {
         APP_DEBUG("app_network_sms_open: connected to %s\n", GW_IP);
         
         config_server_phone_number(fd, data->device_cloud.phone);
         goto done;
    }

    if (status == connector_callback_busy)
    {
        unsigned long elapsed_time;

        app_os_get_system_time(&elapsed_time);
        elapsed_time -= connect_time;

        if (elapsed_time >= APP_CONNECT_TIMEOUT)
        {
            APP_DEBUG("app_network_sms_open: failed to connect withing 30 seconds\n");
            status = connector_callback_error;
        }
    }

error:
    if (status == connector_callback_error)
    {
        APP_DEBUG("app_network_sms_open: failed to connect to %s\n", GW_IP);
        app_dns_set_redirected(connector_class_id_network_sms, 0);

        if (fd >= 0)
        {
            close(fd);
            fd = -1;
        }
    }

done:
    return status;
}

/**
 * @brief   Send data to Device Cloud
 *
 * This routine sends data to Device Cloud. This
 * function must not block. If it encounters EAGAIN or
 * EWOULDBLOCK error, 0 bytes must be returned and
 * Cloud Connector will continue calling this function. If
 * successful connector_callback_continue is returned. If the
 * data could not be sent connector_callback_busy is returned,
 * otherwise connector_callback_abort is returned.
 *
 * @param data @ref connector_network_send_t
 *  <ul>
 *   <li><b><i>handle</i></b> - Network handle </li>
 *   <li><b><i>buffer</i></b> - Data to be sent </li>
 *   <li><b><i>bytes_available</i></b> - Number of bytes to send
 *  </li>
 *   <li><b><i>bytes_used</i></b> - Number of bytes sent </li>
 * </ul>
 *
 * @retval connector_callback_continue	The routine has sent
 *         some data.
 * @retval connector_callback_busy 		No data was sent, the
 *                                  routine has encountered
 *                                  EAGAIN or EWOULDBLOCK error.
 *                                  It will be called again to
 *                                  send data.
 * @retval connector_callback_error     An irrecoverable error has occured,  Cloud Connector will call
 *                                  @ref app_network_sms_close.
 * @retval connector_callback_abort     The application aborts Cloud Connector.
 *
 * @see @ref send API Network Callback
 */
static connector_callback_status_t app_network_sms_send(connector_network_send_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    int * const fd = data->handle;

    int ccode = write(*fd, data->buffer, data->bytes_available);
    if (ccode >= 0)
    {
        data->bytes_used = (size_t)ccode;
    }
    else
    {
        int const err = errno;
        if (err == EAGAIN)
        {
            status = connector_callback_busy;
        }
        else
        {
            status = connector_callback_error;
            APP_DEBUG("app_network_tcp_send: send() failed, errno %d\n", err);
            app_dns_cache_invalidate(connector_class_id_network_tcp);
        }
    }

    return status;
}

/**
 * @brief   Receive data from Device Cloud
 *
 * This routine receives data from Device Cloud. This
 * function must not block.
 *
 * @param data @ref connector_network_receive_t
 *  <ul>
 *   <li><b><i>handle</i></b> - Network handle </li>
 *   <li><b><i>buffer</i></b> - Buffer to place received data
 *   </li>
 *   <li><b><i>bytes_available</i></b> - Buffer size in bytes
 *  </li>
 *   <li><b><i>bytes_used</i></b> - Number of bytes received
 *   </li>
 * </ul>
 *
 * @retval connector_callback_continue	The routine has received some data.
 * @retval connector_callback_busy 		No data is pending, the routine has encountered EAGAIN or
 *                                  EWOULDBLOCK error. It will be called again to receive data.
 * @retval connector_callback_error     An irrecoverable error has occured,  Cloud Connector will call
 *                                  @ref app_network_sms_close.
 * @retval connector_callback_abort     The application aborts Cloud Connector.
 *
 * @see @ref receive API Network Callback
 */
static connector_callback_status_t app_network_sms_receive(connector_network_receive_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    int * const fd = data->handle;

    int ccode = read(*fd, data->buffer, data->bytes_available);
    if (ccode > 0)
    {
        data->bytes_used = (size_t)ccode;
    }
    else
    if (ccode == 0)
    {
        /* EOF on input: the connection was closed. */
        APP_DEBUG("network_receive: EOF on socket\n");
        errno = ECONNRESET;
        status = connector_callback_error;
    }
    else
    {
        int const err = errno;
        /* An error of some sort occurred: handle it appropriately. */
        if (err == EAGAIN)
        {
            status = connector_callback_busy;
        }
        else
        {
            APP_DEBUG("network_receive: recv() failed, errno %d\n", err);
            /* if not timeout (no data) return an error */
            app_dns_cache_invalidate(connector_class_id_network_tcp);
            status = connector_callback_error;
        }
    }

    return status;
}

/**
 * @brief   Close the network
 *
 * This callback requests an application to close it's network handle.
 *
 * @param data @ref connector_network_close_t
 *  <ul>
 *   <li><b><i>handle</i></b> - Network handle </li>
 *   <li><b><i>reconnect</i></b> - Set to connector_true to
 *   reconnect, without exiting connector_run(). Set
 *   to connector_false otherwise.
 *   </li>
 * </ul>
 *
 * @retval connector_callback_continue	The callback has successfully closed the connection.
 * @retval connector_callback_busy 		The network device is busy, the routine will be called again to complete close.
 * @retval connector_callback_abort     The application aborts Cloud Connector.
 *
 * @see @ref connector_callback_status_t
 * @see @ref close API Network Callback
 */
static connector_callback_status_t app_network_sms_close(connector_network_close_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    int * const fd = data->handle;

    app_dns_set_redirected(connector_class_id_network_tcp, data->status == connector_close_status_cloud_redirected);

    data->reconnect = app_connector_reconnect(connector_class_id_network_tcp, data->status);

    if (close(*fd) < 0)
    {
        APP_DEBUG("network_tcp_close: close() failed, fd %d, errno %d\n", *fd, errno);
    }
    else
        APP_DEBUG("network_tcp_close: fd %d\n", *fd);

    *fd = -1;

    return status;
}

/*
 *  Callback routine to handle all networking related calls.
 */
connector_callback_status_t app_network_sms_handler(connector_request_id_network_t const request_id,
                                                    void * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    
    switch (request_id)
    {
    case connector_request_id_network_open:
        status = app_network_sms_open(data);
        break;

    case connector_request_id_network_send:
        status = app_network_sms_send(data);
        break;

    case connector_request_id_network_receive:
        status = app_network_sms_receive(data);
        break;

    case connector_request_id_network_close:
        status = app_network_sms_close(data);
        break;

    default:
        APP_DEBUG("app_network_udp_handler: unrecognized callback request_id [%d]\n", request_id);
        status = connector_callback_unrecognized;
        break;

    }

    return status;
}
#endif