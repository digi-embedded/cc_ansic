/*! @page getting_started Getting Started
 *
 * @htmlinclude nav.html
 *
 * @section table_of_contents_porting Getting Started
 *
 * The Getting Started process will walk you through the steps necessary to get Etherios Cloud Connector integrated into your
 * development environment and running applications which connect to the iDigi Device Cloud.
 *
 * These steps include:
 *
 *          -# @ref step1
 *              -# @ref debug_routine
 *          -# @ref step2
 *          -# @ref step3
 *              -# @ref connector_initialization
 *              -# @ref add_files
 *              -# @ref add_path
 *              -# @ref build_sample
 *          -# @ref step4
 *              -# @ref connector_login
 *              -# @ref connector_vendor_id
 *          -# @ref step5
 *              -# @ref os_routines
 *              -# @ref network_routines
 *              -# @ref configuration_routines
 *              -# @ref application_start
 *          -# @ref step6
 *              -# @ref add_c_files
 *              -# @ref add_include_paths
 *          -# @ref step7
 *          -# @ref step8
 *              -# @ref good_results_output
 *              -# @ref bad_results_output
 *              -# @ref add_your_device_to_the_cloud
 *              -# @ref view_result_on_cloud
 *          -# @ref step9
 *
 * Two sample applications, @ref step3 "compile_and_link" and @ref step7 "connect_to_idigi", will be used to confirm your compilation tool chain
 * and integration, respectively.  When complete, your device will be connected to Etherios Device Cloud and displayed
 * in the <a href="http://www.etherios.com/devicecloud/devicemanager">Device Manager</a>.
 *
 * @section step1 Step 1: Determine if your compiler is C89 or C99 compliant
 *
 * The Etherios Cloud Connector is ANSI X3.159-1989 (ANSI C89) and ISO/IEC 9899:1999 (ANSI C99) compliant.  If
 * your compiler is ANSI C89 or C99 compliant and you are running on a 32-bit processor you can skip
 * to the next section.  (Note the @ref CONNECTOR_RCI_SERVICE "Remote Configuration" feature requires
 * ANSI C99.)
 *
 * If your compiler is not ANSI C89 or C99 compliant, you will have to review (and edit) public/include/connector_types.h
 * to adjust the data types @ref uint8_t, @ref uint16_t, @ref uint32_t, minimum and maxinum values
 * and format specifiers.
 *
 * -# Data types:
 *  @li @ref uint8_t
 *  @li @ref uint16_t
 *  @li @ref uint32_t
 *
 * -# Minimum and maximum values:
 *  @li @ref UINT16_MAX
 *  @li @ref INT32_MIN
 *  @li @ref INT32_MAX
 *  @li @ref UINT32_MAX
 *  @li @ref SIZE_MAX
 *
 * -# Format specifiers:
 *  @li @ref SCNd32
 *  @li @ref SCNu32
 *  @li @ref SCNx32
 *  @li @ref PRId32
 *  @li @ref PRIu32
 *  @li @ref PRIx32
 *
 * Note by default these are defined for a 32-bit machine.
 *
 * @subsection debug_routine Implement the debug routine and macro
 *
 * Open the file debug.c and implement the @ref connector_debug_printf. For the linux platform
 * the file is located at public/run/platforms/linux/debug.c.  Click on the routine
 * to see a description, then modify to operate with your platform. Etherios Cloud Connector calls
 * this routine to display any debug information when @ref CONNECTOR_DEBUG is defined
 * connector_config.h.
 *
 * The file public/include/connector_debug.h implements the a macros listed below, which
 * are used to debug Etherios Cloud Connector.
 *
 *  @li @ref ASSERT
 *
 * Review these definitions and modify these for your platform:
 *
 * If you don't have vprintf or assert available redefine these macros to call corresponding
 * routines for your platform.
 *
 * @section step2 Step 2: Modify connector_config.h
 *
 * Open the file connector_config.h in the sample directory to configure processor endianess.
 *
 * The Etherios Cloud Connector defaults to little endian.  To reconfigure for big endian, comment out the @ref CONNECTOR_LITTLE_ENDIAN define.
 *
 * @section step3 Step 3: Build the compile_and_link sample
 *
 * In this step we are going to build the compile_and_link sample.
 * This sample will verify that your build environment is set up correctly.
 * You need to add the source files and include paths to your build system listed
 * below.
 *
 * @subsection connector_initialization Etherios Cloud Connector Initialization
 *
 * The routine connector_init() is called to initialize Etherios Cloud Connector, currently this is
 * called from the routine main() in main.c; you will need to call connector_init()
 * at the initialization point for your application with an application callback.
 * For the compile_and_link sample you can call connector_init() as:
 *
 * @code
 * // Call connector_init() with a NULL callback to confirm your build environment only
 * connector_init((connector_callback_t)0);
 * @endcode
 *
 * If you are not using main() you will need to add in the call to connector_init()
 * where appropriate.
 *
 * @subsection add_files Add the source files to your build system
 * The following is a list of files required to build.  There is a sample
 * linux Makefile provided (public/run/samples/compile_and_link/Makefile) which you
 * can use as a reference.  Add the following files to your make/build system.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr>
 * <th class="title">Name</th>
 * <th class="title">Description</th>
 * <th class="title">Location</th>
 * </tr>
 * <tr>
 * <td>connector_api.c</td>
 * <td>Contains the code for Etherios Cloud Connector</td>
 * <td>private</td>
 * </tr>
 * <tr>
 * <td>main.c</td>
 * <td>Program entry point, calls @endhtmlonly connector_init() @htmlonly</td>
 * <td>public/run/samples/compile_and_link</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * @subsection add_path Add the include paths
 * The following is a list of include paths to add to your system:
 *
 * @li public/include
 *
 * @subsection add_define Add the defines
 *
 * The following define is required, and used to indicate that the version of
 * Etherios Cloud Connector is 1.2
 *
 * @li CONNECTOR_VERSION=0x1020000UL
 *
 * @subsection build_sample Build the sample
 *
 * Now that you have the build environment setup, verify the compilation and link.  If
 * you using the Makefile provided, type @htmlonly"<I>make clean all</I>"@endhtmlonly in
 * the compile_and_link directory, otherwise perform a build ni your environment.
 * If you are experiencing a build problem, double check the steps listed above.  There
 * is only one include path and two C files required to build this sample. Once the build
 * is successful you can proceed to the next step.
 *
 * @note Do not execute the compile_and_link sample, as this only verifies that the build environment
 * is set up correctly. The application will exit on a failed ASSERT when run.
 *
 * @section step4 Step 4: Setup your iDigi Device Cloud Account
 *
 * @subsection connector_account Create an iDigi Device Cloud Account
 * Before getting started you will need to create a new iDigi Device Cloud account and obtain a unique iDigi Device Cloud Vendor ID (which is
 * a unique identifier for your company).
 *
 * Later in this process, when you get the connect_to_idigi sample @ref good_results_output "running successfully", you will be @ref add_your_device_to_the_cloud "instructed to register"
 * your Device ID with the iDigi Device Cloud.
 *
 * To create an account, navigate to
 * https://my.idigi.com/user_registration.do and follow the instructions to create and register your
 * iDigi Device Cloud account.
 *
 * @note If you have already created and registered an iDigi Device Cloud Account, navigate here
 * https://my.idigi.com/ and follow the instructions in the next step.
 *
 * @image html cloud_registration.png
 *
 * @subsection connector_login Login to the iDigi Device Cloud
 * 1. Login with the user credentials you created in section @ref connector_account
 *
 * @image html cloud_login.png
 *
 * @subsection connector_vendor_id Obtain an iDigi Device Cloud Vendor ID
 * 2. If you are a first time iDigi Device Cloud developer, you will need to obtain an iDigi Device Cloud Vendor ID.  To
 * obtain an iDigi Device Cloud Vendor ID, select the Register for new vendor id button on the bottom of
 * the @b My @b Account section under @b Administration tab after successfully logging into https://my.idigi.com/.
 *
 * @image html cloud_vendor_id.png
 *
 * After selecting the register for a Vendor ID button, the page will refresh and your unique vendor ID number
 * will be displayed in place of the button.  Record the Vendor ID, you will need it later.
 *
 * @note If you already have a vendor ID, it will be displayed instead of the button.
 *
 * @section step5 Step 5: Porting your platform for the connect_to_idigi sample
 *
 * The @b connect_to_idigi sample validates the most fundamental Etherios Cloud Connector porting aspects.  If you can successfully connect and stay
 * connected to the iDigi Device Cloud, all other Etherios Cloud Connector functions (like @ref put_request "sending data" or @ref firmware_download "firmware download")
 * should work without failure.
 *
 * Go into the platforms directory and select a platform which is similar to your platform.  If
 * none of the available platforms are similar to yours, you can use the template platform.
 *
 * In this guide we use the public/run/platforms/linux as an example, but all platforms have the same structure.
 * So choose a platform (or copy an existing one) and go into that directory.
 *
 * @subsection os_routines OS Routines
 * Open the file os.c and implement the routines listed below.  For the linux platform
 * the file is located at public/run/platforms/@a my_platform/os.c.  Click on the routine
 * to see a description, then modify to operate with your platform.  These routines
 * are callbacks which are described in the API section.
 *
 *  @li app_os_malloc()
 *  @li app_os_free()
 *  @li app_os_get_system_time()
 *  @li app_os_reboot()
 *  @li app_os_status()
 *
 * @subsection network_routines Network Routines
 * Open the file network_tcp.c and implement the network interface routines.
 * The network interface routines provided in the Linux platform are implemented using standard
 * Berkeley socket calls and can be used as a reference for your platform.
 * You may have to modify the routines in this file based on your
 * platforms network implementation.
 *
 * The following is a list of network interface routines which must be implemented:
 *  @li app_network_tcp_open()
 *  @li app_network_tcp_send()
 *  @li app_network_tcp_receive()
 *  @li app_network_tcp_close()
 *
 * @subsection configuration_routines Configuration Routines
 *
 * In this step we set up the configuration routines for your platform. Each configuration
 * item has a corresponding get routine for retrieving its value. Open the file config.c
 * for your platform and implement the configuration routines.
 * All configuration routines are passed in a pointer to a pointer, along with a pointer to the size.
 * The address of the configuration item is stored in the pointer passed in, and the size is assigned to the pointer to the size variable.
 * For example, app_get_vendor_id() is the routine used to retrieve the iDigi Device Cloud account Vendor ID
 * and is shown below.
 * @code
 * static connector_callback_status_t app_get_vendor_id(uint8_t const ** id, size_t * const size)
 * {
 * #error  "Specify vendor id"
 *     #define VENDOR_ID_LENGTH    4
 *
 *    static uint8_t const device_vendor_id[VENDOR_ID_LENGTH] = {0x00, 0x00, 0x00, 0x00};
 *
 *    *id   =  device_vendor_id;
 *    *size = sizeof device_vendor_id;
 *
 *    return connector_callback_continue;
 * }
 * @endcode
 *
 * @note The required routines contain the @htmlonly #error @endhtmlonly preprocessor directive
 * which must be removed before compiling.
 *
 * @note The memory assigned to configuration items must be @b statically @b allocated and is accessed by Etherios Cloud Connector
 * after the routine returns.
 *
 * The following is a list of configuration routines which need to be implemented for
 * your platform, please review each routine:
 *  @li app_get_ip_address()
 *  @li app_get_mac_addr()
 *  @li app_get_device_id()
 *  @li app_get_vendor_id()
 *  @li app_get_device_type()
 *  @li app_get_server_url()
 *  @li app_get_connection_type()
 *  @li app_get_link_speed()
 *  @li app_get_phone_number()
 *  @li app_get_tx_keepalive_interval()
 *  @li app_get_rx_keepalive_interval()
 *  @li app_get_wait_count()
 *  @li app_get_firmware_support()
 *  @li app_get_data_service_support()
 *  @li app_get_file_system_support()
 *  @li app_get_remote_configuration_support()
 *  @li app_get_max_message_transactions()
 *  @li app_get_device_id_method()
 *  @li app_get_wan_type()
 *  @li app_get_imei_number()
 *  @li app_get_esn()
 *  @li app_get_meid()
 *  @li app_get_identity_verification()
 *  @li app_get_password()
 *  @li app_config_error()
 *
 * @note For information on using hard coded values instead of these configuration callbacks,
 *       which helps to reduce Etherios Cloud Connector code space,  see @ref connector_config_data_options
 *
 * @subsection application_start iDigi Connector Initialization
 *
 * As in the @ref step3 "compile_and_link" sample, you must make a call to connector_init().  However, in
 * this sample, you will execute the code, making all the networking, configuration, and operating
 * system callbacks.
 *
 * The connector_init() call, must now include a proper callback:
 *
 * @code
 * // Initialize Etherios Cloud Connector with the application callback
 * connector_handle = connector_init(app_connector_callback);
 * @endcode
 *
 * and placed in location capable of starting a network client.
 *
 * Its recommended that you use the code inside main() and cut and paste, as is, into an appropriate spot.
 * In the Linux platform provided, the routine main() creates a thread which then calls connector_run().  You
 * will need to set up a similar thread in your environment (or call connector_step()) periodically.
 *
 * This thread is shown below:
 * @code
 * static void * connector_run_thread(void * arg)
 * {
 *     connector_status_t status;
 *
 *     APP_DEBUG("connector_run thread starts\n");
 *
 *     // Run Etherios Cloud Connector, this will only return on an Etherios Cloud Connector abort
 *     status = connector_run(arg);
 *
 *     APP_DEBUG("connector_run thread exits %d\n", status);
 *
 *     pthread_exit(arg);
 * }
 * @endcode
 *
 * @note The connector_init() call must successfully complete prior to any other Etherios Cloud Connector call (i.e., connector_run(), connector_step()).
 *
 * @section step6 Step 6: Setup your build environment
 *
 * @subsection add_c_files Add the source files to your build system
 *
 * To build the connect_to_idigi sample you will need to add the files shown below
 * to your build environment.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr>
 * <th class="title">Name</th>
 * <th class="title">Description</th>
 * <th class="title">Location</th>
 * </tr>
 * <tr>
 * <td>connector_api.c</td>
 * <td>Contains the code for Etherios Cloud Connector</td>
 * <td>private</td>
 * </tr>
 * <tr>
 * <td>application.c</td>
 * <td>Contains the code which runs the sample and main callback that calls
 * callbacks in os.c, network_tcp.c, and config.c</td>
 * <td>public/run/samples/connect_to_idigi</td>
 * </tr>
 * <tr>
 * <td>os.c</td>
 * <td>Operating System Routines</td>
 * <td>public/run/platforms/<i>my_platform</i></td>
 * </tr>
 * <tr>
 * <td>network_tcp.c</td>
 * <td>Network Interface</td>
 * <td>public/run/platforms/<i>my_platform</i></td>
 * </tr>
 * <tr>
 * <td>config.c</td>
 * <td>Configuration Routines</td>
 * <td>public/run/platforms/<i>my_platform</i></td>
 * </tr>
 * <tr>
 * <td>main.c (if applicable)</td>
 * <td>Program entry point, calls @endhtmlonly connector_init() @htmlonly</td>
 * <td>public/run/platforms/<i>my_platform</i></td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * @subsection add_include_paths Add the include paths
 *
 * The following is a list of include paths you will need to add to your build
 * system:
 *
 * @li public/include
 * @li run/platforms/@a my_platform
 *
 * @section step7 Step 7: Build the connect_to_idigi sample
 * Next, build the sample.  If you are running on Linux you can simply type: @htmlonly"<I>make clean all</I>"@endhtmlonly
 * in the public/run/samples/connect_to_idigi, if you are not using Linux then
 * you will have to build for your environment.
 *
 * @section step8 Step 8: Run the connect_to_idigi sample
 * The name of the executable generated by the Linux Makefile is called idigi.
 * In Linux, type ./idigi from a console to execute the program.
 *
* @note By default @ref CONNECTOR_DEBUG is defined in connector_config.h, which prints helpful Etherios Cloud Connector Library debug
 * messages to the standard output.
 *
 * @subsection good_results_output Example output from a successful run of connect_to_idigi
 * Below is the standard output shown for a successful @ref step7 "connect_to_idigi" run:
 *
 * @code
 *  >./idigi
 * Start iDigi
 * iDigi Connector v1.2.0.0
 * vendor id: 0x1000001
 * connector_run thread starts
 * application_run thread starts
 * application_run thread exits 0
 * dns_resolve_name: ip address = [50.56.41.153]
 * network_connect: connected to [my.idigi.com] server
 * communication layer: Send MT Version
 * communication layer: receive Mt version
 * communication layer: send keepalive params
 * communication layer: Rx keepalive parameter = 60
 * communication layer: Tx keepalive parameter = 90
 * communication layer: Wait Count parameter = 5
 * initialization layer: send protocol version
 * initialization layer: receive protocol version
 * Security layer: send security form
 * get_connection_type: connection type = 0
 * get_mac_addr: MAC address =  78 E7 D1 84 47 82
 * security layer: send device ID =  00 00 00 00 00 00 00 00 78 E7 D1 FF FF 84 47 82
 * security layer: send server url = my.idigi.com
 * discovery layer: send vendor id =  01 00 00 01
 * discovery layer: send device type = Linux Application
 * Connection Control: send redirect_report
 * Connection Control: send connection report
 * get_ip_address: Looking for current device IP address: found [2] entries
 * get_ip_address: 1: Interface name [lo]  IP Address [127.0.0.1]
 * get_ip_address: 2: Interface name [eth1]        IP Address [10.52.18.75]
 * get_ip_addr: Device IP address =  0A 34 12 4B
 * get_connection_type: connection type = 0
 * get_mac_addr: MAC address =  78 E7 D1 84 47 82
 * discovery layer: send complete
 * @endcode
 *
 * @subsection bad_results_output Locating helpful error info in Etherios Cloud Connector standard output
 *
 * When an error occurs, since APP_DEBUG is defined as printf in your platform.h file, critical errors are
 * displayed via the @ref connector_config_error_status callback.  Below is an example with an output showing an error
 * related to the @ref connector_config_server_url callback.  By searching through your application code, you can
 * easily trace this callback to the app_get_server_url() porting function:
 *
 * @code
 *  >./idigi
 *  Start iDigi
 *  initialize_facilities: callback supports  13 facility
 *  initialize_facilities: callback supports  14 facility
 *  connector_run thread starts
 *  application_run thread exits 0
 *  connector_run thread starts
 *  connector_error_status: Config - connector_config_server_url (3)  status = connector_invalid_data_range (4)
 *  connector_run thread exits 4
 *  >
 * @endcode
 *
 * Given this output, a thorough code review of the app_get_server_url() function should reveal a porting defect.
 *
 * @subsection add_your_device_to_the_cloud Add your Device to the iDigi Device Cloud
 *
 * The next several sections walk through the steps required to add your device to
 * the iDigi Device Cloud.
 *
 *  -# Navigate to http://my.idigi.com and log on to the iDigi Device Cloud
 *  -# Click on the iDigi Manager Pro tab.
 *  -# Click the Add Devices button (the + button under Devices) to bring up the Add Devices dialog.
 *
 * @image html cloud_add_device_button.png
 *
 * Within the Add Devices dialog click the Add Manually>> button.
 *
 * @image html cloud_add_device_manually.png
 *
 * Select Device ID: from the drop-down menu.
 *
 * @image html cloud_add_device_select_device_id.png
 *
 * Enter the Device ID for your device then click the Add button.
 *
 * @image html cloud_add_device_enter_device_id.png
 *
 * Click the OK button to add your device to the iDigi Device Cloud.
 *
 * @image html cloud_add_device_click_ok.png
 *
 * @subsection view_result_on_cloud Viewing Results on the iDigi Device Cloud
 *
 * Click the Refresh button. The device will reconnect to the iDigi Device Cloud.
 * If successful your device Status will show connected.  You can now communicate
 * with your device over the iDigi Device Cloud.  The next step
 * is to integrate in one of the samples to add in more functionality to your
 * application.
 *
 * @note If you cannot connect to the iDigi Device Cloud, the most likely problem
 * is in the iDigi Connector Configuration, review the configuration routines in config.c;
 * The device ID and vendor ID must be valid to connect.
 *
 * @image html cloud_device_connected.png
 *
 * @section step9 Step 9: Next Steps
 *
 * Now that you have a basic sample up and running with the iDigi Device Cloud, you
 * can port in more functionality to your application.  We first suggest
 * reading the @ref api1_overview "API" section of the documentation and then
 * select a sample which has the functionality you need.
 *
 * @note If using the Linux makefiles, when compiling and running a different sample,
 * always build clean: @htmlonly"<I>make clean all</I>"@endhtmlonly before running.
 *
 * @htmlinclude terminate.html
 */

