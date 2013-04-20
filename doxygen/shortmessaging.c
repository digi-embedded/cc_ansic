/*! @page shortmessaging Short Messaging
 *
 * @htmlinclude nav.html
 *
 * @section secsmintroduction Short Messaging Introduction
 *
 * Short Message (SM) is a lightweight, message oriented protocol that
 * allows applications to optimize network data usage.
 *
 * This chapter will explain:
 *
 *   -# @ref smwhatisit
 *        -# @ref smtransports
 *   -# @ref smsectionwhoneedsit
 *        -# @ref smsectionwhodoesnotneedsit
 *   -# @ref smsolutions
 *        -# @ref smcomplications
 *   -# @ref smsecurity
 *   -# @ref smsectionexamples
 *
 * @section smwhatisit What is Short Messaging?
 *
 * The Short Message (SM) protocol was designed to be a lightweight, message oriented
 * protocol suitable for use on transports that are:
 *    @li Expensive or where data usage needs to be kept to a minimum.
 *    @li Lossy
 *       -# Delivery not guaranteed
 *       -# Duplicates possible
 *       -# Data integrity not guaranteed
 *
 * The SM protocol supports the following commands: Reboot, Status Request (similar to a ping),
 * and Data transfer.
 *
 * The SM protocol defines a set of encodings and supported commands and the expected behavior
 * for those commands.  There are some aspects to the protocol that are transport specific.
 *
 * THe Etherios Cloud Connector supports only the UDP transport for Short Messaging.  In the
 * future, SMS will be supported.
 *
 * @subsection smtransports Why is the transport important?
 *
 * From the top level these callbacks are analogous to the @ref network_callbacks.
 * Internally they provide interface to securely connect to Etherios Device Cloud
 * on SSL. Any application can make use of these APIs to obtain secure connection
 * just by including network_tcp_ssl.c instead of network_tcp.c. The sample application
 *
 * @section smsectionwhoneedsit Who needs Short Messaging?
 *
 * From the top level these callbacks are analogous to the @ref network_callbacks.
 * Internally they provide interface to securely connect to Etherios Device Cloud
 * on SSL. Any application can make use of these APIs to obtain secure connection
 * just by including network_tcp_ssl.c instead of network_tcp.c. The sample application
 *
 * @subsection smsectionwhodoesnotneedsit Who doesn't need Short Messaging?
 *
 * From the top level these callbacks are analogous to the @ref network_callbacks.
 * Internally they provide interface to securely connect to Etherios Device Cloud
 * on SSL. Any application can make use of these APIs to obtain secure connection
 * just by including network_tcp_ssl.c instead of network_tcp.c. The sample application
 *
 * @section smsolutions How does Short Messaging solve my problem?
 *
 * From the top level these callbacks are analogous to the @ref network_callbacks.
 * Internally they provide interface to securely connect to Etherios Device Cloud
 * on SSL. Any application can make use of these APIs to obtain secure connection
 * just by including network_tcp_ssl.c instead of network_tcp.c. The sample application
 *
 * @subsection smcomplications How does Short Messaging complicate my application?
 *
 * From the top level these callbacks are analogous to the @ref network_callbacks.
 * Internally they provide interface to securely connect to Etherios Device Cloud
 * on SSL. Any application can make use of these APIs to obtain secure connection
 * just by including network_tcp_ssl.c instead of network_tcp.c. The sample application
 *
 * @section smsecurity Short Messaging Security
 *
 * From the top level these callbacks are analogous to the @ref network_callbacks.
 * Internally they provide interface to securely connect to Etherios Device Cloud
 * on SSL. Any application can make use of these APIs to obtain secure connection
 * just by including network_tcp_ssl.c instead of network_tcp.c. The sample application
 *
 * @section smsectionexamples Short Messaging examples
 *
 * From the top level these callbacks are analogous to the @ref network_callbacks.
 * Internally they provide interface to securely connect to Etherios Device Cloud
 * on SSL. Any application can make use of these APIs to obtain secure connection
 * just by including network_tcp_ssl.c instead of network_tcp.c. The sample application
 *
 * @htmlinclude terminate.html
 */
