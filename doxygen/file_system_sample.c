/*! @page file_system_sample File System Sample
 *
 * @htmlinclude nav.html
 *
 * @section fs_sample_overview Overview
 *
 * This sample demonstrates how to read, write, and delete files and list files or directories on your device,
 * using the @ref file_system_overview1 "file system API".
 *
 * @section fs_sample_location Source Code Location
 *
 *      - For the connector_run() version:
 *           - @htmlonly<I>/connector/public/run/samples/file_system</I>@endhtmlonly
 *
 *      - For the connector_step() version:
 *          - @htmlonly<I>/connector/public/step/samples/file_system</I>@endhtmlonly
 *
 * @note Check @ref threading "here for more information" on using the connector_run()
 * versus connector_step() model.
 *
 * @section fs_sample_description Code Flow
 *
 * The routine main() in the platform directory initializes Etherios Cloud Connector and registers the application callback
 * app_connector_callback() as part of @ref AppStructure "Public Application Framework". The app_connector_callback()
 * is defined in the application.c file. The app_connector_callback() callback calls app_file_system_handler(),
 * defined in the file_system.c file in the platform directory, when a file system request is received.
 *
 * All file system requests are initiated by Etherios Device Cloud.
 *
 * The app_file_system_handler() routine calls the following routines to perform different file I/O operations:
 *
 * @htmlonly
 * <table class="apitable">
 * <tr>
 * <th class="title">Routine</th>
 * <th class="title">Operation</th>
 * <th class="title">Request Id</th>
 * </tr>
 * <tr>
 * <td>app_process_file_open()</td><td>@endhtmlonly @ref file_system_open @htmlonly</td><td>@endhtmlonly @ref connector_file_system_open @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_lseek()</td><td>@endhtmlonly @ref file_system_lseek @htmlonly</td><td>@endhtmlonly @ref connector_file_system_lseek @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_read()</td><td>@endhtmlonly @ref file_system_read @htmlonly</td><td>@endhtmlonly @ref connector_file_system_read @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_write()</td><td>@endhtmlonly @ref file_system_write @htmlonly</td><td>@endhtmlonly @ref connector_file_system_write @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_ftruncate()</td><td>@endhtmlonly @ref file_system_ftruncate @htmlonly</td><td>@endhtmlonly @ref connector_file_system_ftruncate @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_close()</td><td>@endhtmlonly @ref file_system_close @htmlonly</td><td>@endhtmlonly @ref connector_file_system_close @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_rm()</td><td>@endhtmlonly @ref file_system_rm @htmlonly</td><td>@endhtmlonly @ref connector_file_system_rm @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_opendir()</td><td>@endhtmlonly @ref file_system_opendir @htmlonly</td><td>@endhtmlonly @ref connector_file_system_opendir @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_readdir()</td><td>@endhtmlonly @ref file_system_readdir @htmlonly</td><td>@endhtmlonly @ref connector_file_system_readdir @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_closedir()</td><td>@endhtmlonly @ref file_system_closedir @htmlonly</td><td>@endhtmlonly @ref connector_file_system_closedir @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_stat()</td><td>@endhtmlonly @ref file_system_stat @htmlonly</td><td>@endhtmlonly @ref connector_file_system_stat @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_hash()</td><td>@endhtmlonly @ref file_system_hash @htmlonly</td><td>@endhtmlonly @ref connector_file_system_hash @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_strerror()</td><td>@endhtmlonly @ref file_system_strerror @htmlonly</td><td>@endhtmlonly @ref connector_file_system_strerror @htmlonly</td>
 * </tr>
 * <tr>
 * <td>app_process_file_msg_error()</td><td>@endhtmlonly @ref file_system_msg_error @htmlonly</td><td>@endhtmlonly @ref connector_file_system_msg_error @htmlonly</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * @section fs_sample_hash_support File Hash Values Support
 *
 * By default the file system sample does not support file hash values. MD5 support can be enabled using the following define:
 *
 * -DAPP_ENABLE_MD5=true
 *
 * When MD5 support is enabled the sample uses MD5_Init(), MD5_Update(), and MD5_Final() functions
 * from the openssl library.
 *
 * @section fs_sample_python_script Python script to write, read, and list a file
 *
 * This sample provides a simple python script file_system.py to write, read, and list a file,
 * using @htmlonly <a href="web_services.html">iDigi Web Services</a> @endhtmlonly.
 *
 * It sends a request to login.etherios.com. The file "test_file.txt" is created in the current directory
 * on the device with the file data "Connector file system sample\n".
 *
 * To run the python script in the sample, type:
 *
 * @code
 * python file_system.py <username> <password> <device_id>
 * @endcode
 *
 * The part of the python script which contains file system commands looks like:
 *
 * @code
 *
 *  expected_content = "Connector file system sample\n"
 *  put_data = base64.encodestring(expected_content)[:-1]
 *
 *  # file system message to send to server
 *  message = """<sci_request version="1.0">
 *      <file_system>
 *          <targets>
 *              <device id="%s"/>
 *          </targets>
 *          <commands>
 *              <put_file path="test_file.txt" offset = "0" truncate = "true">
 *                <data>%s</data>
 *              </put_file>
 *              <get_file path="test_file.txt" offset = "0" length = "4294967294"/>
 *              <ls path="test_file.txt"/>
 *          </commands>
 *      </file_system>
 *  </sci_request>
 *  """ % (device_id, put_data, ls_path)
 *
 * @endcode
 *
 * @section fs_sample_put_file The put_file command
 *
 * The put_file command initiates a file system session, which writes a file on the device.
 * Etherios Cloud Connector will invoke the following application callbacks:
 *
 *  -# @ref file_system_open "app_process_file_open()" is called with the "test_file.txt" path and
 *          @ref CONNECTOR_O_WRONLY | @ref CONNECTOR_O_CREAT oflag
 *  -# @ref file_system_write "app_process_file_write()" is called with the file descriptor and file data
 *  -# @ref file_system_close "app_process_file_close()" is called with the file descriptor
 *
 * The put_file command could be used to write part of the file.
 * If the put_file command is issued with non-zero offset, Etherios Cloud Connector then would call
 * @ref file_system_lseek "app_process_file_lseek()" callback to set the file position.
 *
 * @section fs_sample_get_file The get_file command
 *
 * The get_file command initiates a file system session, which reads a file and sends file data
 * to Etherios Device Cloud. Etherios Cloud Connector will invoke the following application callbacks:
 *
 *  -# @ref file_system_open "app_process_file_open()" is called with the "test_file.txt" path and
 *          @ref CONNECTOR_O_RDONLY oflag
 *  -# @ref file_system_read "app_process_file_read()" is called with the file descriptor and pointer to the data buffer
 *  -# @ref file_system_close "app_process_file_close()" is called with the file descriptor
 *
 * The get_file command could be used to read part of the file. If the get_file command is issued with non-zero offset,
 * Etherios Cloud Connector then would call @ref file_system_lseek "app_process_file_lseek()" callback to set the file position.
 *
 * @section fs_sample_ls_file The ls command
 *
 * The ls command initiates a file system session, which lists a file or directory.
 * In this example Etherios Cloud Connector will invoke the following application callback:
 *
 *  @ref file_system_stat "app_process_file_stat()" is called with the "test_file.txt" path and
 *          @ref connector_file_hash_none hash_alg.
 *
 * The directory path could be used instead of the file path to list a directory. The following command
 * can be used to list a current directory and use MD5 hash algorithm:
 *
 * @code
 *
 *      <ls path="./" hash = "md5"/>
 *
 * @endcode
 *
 * Etherios Cloud Connector will invoke the following application callbacks:
 *
 *  -# @ref file_system_stat "app_process_file_stat()" called with the "./" path and
 *          @ref connector_file_hash_md5 hash_alg
 *  -# @ref file_system_opendir "app_process_file_opendir()" called with the "./" path
 *  -# For each entry in the directory:
 *      -# @ref file_system_readdir "app_process_file_readdir()", called with the handle, returned in
 *              @ref file_system_opendir "app_process_file_opendir()"
 *      -# @ref file_system_stat "app_process_file_stat()" is called with an entry path and @ref connector_file_hash_none hash_alg
 *      -# @ref file_system_hash "app_process_file_hash()" is called with an entry path and @ref connector_file_hash_md5 hash_alg
 *  -# @ref file_system_closedir "app_process_file_closedir()" is called with the handle, returned in
 *              @ref file_system_opendir "app_process_file_opendir()"
 *
 * The file_system.c sample uses the re-entrant function readdir_r() to read the next directory entry.
 * @ref file_system_opendir "app_process_file_opendir()" allocates memory to hold
 * a directory entry and a pointer to a directory stream and returns this pointer in the response_data->handle.
 * The @ref file_system_closedir "app_process_file_closedir()" callback frees this memory.
 *
 * The memory buffer, used for MD5 calculations for each file in the directory, is allocated in the
 * @ref file_system_stat "app_process_file_stat()" function called with the directory path "./" and then used
 * for each file in this directory. The pointer to the memory buffer is passed between callbacks in response_data->user_context.
 * The @ref file_system_closedir "app_process_file_closedir()" callback frees the memory buffer.
 *
 * @section fs_sample_rm_file The rm command
 *
 * The sample python script does not remove the file. The following command could be added to remove test_file.txt:
 *
 * @code
 *
 *    <rm path="test_file.txt"/>
 *
 * @endcode
 *
 * Etherios Cloud Connector will invoke the @ref file_system_rm "app_process_file_rm()" callback.
 *
 * @section fs_sample_output Sample output
 *
 * Application output is:
 *
 * @code
 *
 * Open test_file.txt, 577, returned 4
 * write 4, 25, returned 25
 * close 4 returned 0
 * Open test_file.txt, 0, returned 4
 * read 4, 496, returned 25
 * read 4, 471, returned 0
 * close 4 returned 0
 * stat for test_file.txt returned 0, filesize 25
 *
 * @endcode
 *
 * Output from the file_system.py is:
 *
 * @code
 *
 * Response:
 * <sci_reply version="1.0">
 *    <file_system>
 *       <device id="00000000-00000000-00000000-00000000">
 *          <commands>
 *             <put_file/>
 *             <get_file><data>aURpZ2kgZmlsZSBzeXN0ZW0gc2FtcGxlCg==</data></get_file>
 *             <ls hash="none"><file path="test_file.txt" last_modified="1334009380" size="25"/></ls>
 *          </commands>
 *       </device>
 *    </file_system>
 * </sci_reply>
 *
 * @endcode
 *
 * @section fs_sample_build Building
 *
 * To build this example on a Linux system, go to the public/run/samples/file_system
 * directory and type: @htmlonly"<I>make clean all</I>"@endhtmlonly.
 * If you are not using Linux you will need to update your environment with
 * the information below and then build the image for your platform.
 *
 * @note To build this example for Linux with MD5 checksums,
 * type: @htmlonly"<I>make APP_ENABLE_MD5=true clean all</I>"@endhtmlonly.
 *
 * @subsection source_files Source Files
 *
 * The following is a list of source files required to build this sample:
 *
 * @htmlonly
 * <table class="apitable">
 * <tr>
 * <th class="title">Name</th>
 * <th class="title">Description</th>
 * <th class="title">Location</th>
 * </tr>
 * <tr>
 * <td>application.c</td>
 * <td>Contains application_run() and the application callback</td>
 * <td>samples/file_system</td>
 * </tr>
 * <tr>
 * <td>status.c</td>
 * <td>Status calls</td>
 * <td>samples/file_system</td>
 * </tr>
 * <tr>
 * <td>file_system.py</td>
 * <td>Python script to write, read, and list a file</td>
 * <td>samples/file_system</td>
 * </tr>
 * <tr>
 *   <th>connector_config.h</th>
 *   <td> iDigi Connector options</td>
 *   <td>samples/file_system</td>
 * </tr>
 * <tr>
 * <td>connector_api.c</td>
 * <td>Code for Etherios Cloud Connector </td>
 * <td>private</td>
 * </tr>
 * <tr>
 * <td>file_system.c</td>
 * <td>Application callbacks for file system</td>
 * <td>platforms/<i>my_platforme</i></td>
 * </tr>
 * <tr>
 * <td>os.c</td>
 * <td>Operating system calls</td>
 * <td>platforms/<i>my_platform</i></td>
 * </tr>
 * <tr>
 * <td>network_tcp.c</td>
 * <td> Network interface Network interface for TCP</td>
 * <td>platforms/<i>my_platform</i></td>
 * </tr>
 * <tr>
 * <td>config.c</td>
 * <td>Configuration routines</td>
 * <td>platforms/<i>my_platform</i></td>
 * </tr>
 * <tr>
 * <td>main.o</td>
 * <td>Starting point of program, dependent on build environment</td>
 * <td>platforms/<i>my_platform</i></td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * @subsection include_paths Include Paths
 *
 * The following include paths are required:
 *
 * @li public/include
 * @li run/platforms/linux (substitute with your platform)
 *
 * @htmlinclude terminate.html
 */
