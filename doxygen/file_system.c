/*! @page file_system File System
 *
 * @htmlinclude nav.html
 *
 * @section file_system_overview1 File System
 *
 *  -# @ref file_system_overview
 *  -# @ref file_system_context
 *  -# @ref file_system_term
 *  -# @ref file_system_open
 *  -# @ref file_system_lseek
 *  -# @ref file_system_read
 *  -# @ref file_system_write
 *  -# @ref file_system_truncate
 *  -# @ref file_system_close
 *  -# @ref file_system_remove
 *  -# @ref file_system_opendir
 *  -# @ref file_system_readdir
 *  -# @ref file_system_closedir
 *  -# @ref file_system_stat
 *  -# @ref file_system_stat_dir_entry 
 *  -# @ref file_system_hash
 *  -# @ref file_system_get_error
 *  -# @ref file_system_session_error
 * <br /><br />
 *
 * @section file_system_overview Overview
 *
 * The file system facility is an optional facility for applications to access files on the device 
 * remotely from Etherios Device Cloud. The Etherios Cloud Connector invokes the application-defined callbacks  
 * to read from a file, to write to a file, and to list files or directory entries.
 *
 * The largest file allowed by Device Cloud to get from the device is 2MB - 1byte (2097151 bytes). 
 *
 * A typical application-defined callback sequence for reading file data by Etherios Device Cloud would include:
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_open "file open" callback with read-only access.
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_read "file read" callback number of times, until
 *     the requested data amount is retrieved or the end of the file is reached.
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_close "file close" callback.
 *
 * A typical application-defined callback sequence for writing file data by Etherios Device Cloud would include:
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_open "file open" callback with write-create access.
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_write "file write" callback number of times, untill all data,
 *     received from Etherios Device Cloud, is written to the file.
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_close "file close" callback.
 *
 * In order to remove a file Etherios Cloud Connector calls application-defined @ref file_system_remove "file remove" callback.
 *
 * A typical application-defined callback sequence to get listing for a single file would be:
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_stat "get status" callback. 
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_hash "get file hash value" callback, if the requested hash value is supported.
 *
 * A typical application-defined callback sequence to get a directory listing would be:
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_stat "get status" callback and learns that the path is a directory.
 *  -# Etherios Cloud Connector calls application-defined @ref file_system_opendir "open a directory" callback.
 *  -# For each directory entry Etherios Cloud Connector invokes application-defined callbacks:
 *      -# @ref file_system_readdir "read a directory entry" callback.
 *      -# @ref file_system_stat "get status for a directory entry" callback.
 *      -# @ref file_system_hash "get file hash value" callback, if the requested hash value is supported.
 *  -# When all directory entries are processed, Etherios Cloud Connector calls application-defined @ref file_system_closedir "close a directory" callback.
 *
 * @note See @ref file_system_support under Configuration to enable or disable file system.
 * <br /><br />
 *
 * @section file_system_context Session Context
 *
 * Data structures for all file system callbacks have the <b><i>user_context</i></b> field. This field is provided to 
 * the application to identify the session and store session data between callbacks. 
 *
 * All application session memory must be released in the last callback of the session, typically 
 * @ref file_system_close "close a file" or @ref file_system_closedir "close a directory" callbacks.
 * This callback will be invoked if the file or directory was opened successfully, even if the session had an error.
 * <br /><br />
 *
 * @section file_system_term Session Termination and Error Processing
 * 
 * Data structures for all file system callbacks have the <b><i>void * errnum</i></b> field. If a callback encounters an error
 * it should set <b><i>errnum</i></b> to some user defined error token, for example <i>errno</i>, and return @ref connector_callback_error.
 * The errnum will be later used in @ref file_system_get_error "get error description" callback
 * to translate this user defined error token to an error status and error description to to send to Etherios Device Cloud. 
 * 
 * Different scenarios for the session termination are described below.
 *
 * If the session is successful:
 *  -# Etherios Cloud Connector calls @ref file_system_close "close a file" or @ref file_system_closedir "close a directory" callback, 
 *     if there is an open file or directory.
 *  -# Etherios Cloud Connector sends the last response to Etherios Device Cloud.
 *
 * The callback aborts Etherios Cloud Connector:
 *  -# The callback returns @ref connector_callback_abort status.
 *  -# Etherios Cloud Connector calls @ref file_system_close "close a file" or @ref file_system_closedir "close a directory" callback, 
 *     if there is an open file or directory.
 *  -# Etherios Cloud Connector is aborted.
 *
 * The callback encounters a error while performing the requested operation:
 *  -# The callback returns @ref connector_callback_error and <b><i>errnum</i></b>.
 *  -# Etherios Cloud Connector calls @ref file_system_close "close a file" or @ref file_system_closedir "close a directory" callback, 
 *     if there is an open file or directory.
 *  -# If Etherios Cloud Connector has already sent part of file or directory data, it cancels the session. This is due to the fact 
 *     that it can't differentiate an error response from part of the data response.
 *  -# Otherwise Etherios Cloud Connector calls @ref file_system_get_error "get error description" callback and sends an error response to Etherios Device Cloud.
 *
 * File system was notified of a session error:
 *  -# Etherios Cloud Connector calls @ref file_system_msg_error "session error" callback.
 *  -# Etherios Cloud Connector calls @ref file_system_close "close a file" or @ref file_system_closedir "close a directory" callback, 
 *     if there is an open file or directory.
 *  -# Etherios Cloud Connector canceles the session.
 * <br /><br />
 *
 * @section file_system_open Open a file
 *
 * Open a file for the specified path. 
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_open @htmlonly</td>
 * </tr>
 * <tr>
 *   <th>data</th>
 *   <td> pointer to @endhtmlonly @ref connector_file_system_open_t "connector_file_system_open_t" @htmlonly structure where:
 *     <ul>
 *       <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *       <br /> 
 *       <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *       <br /> 
 *       <li><b><i>path</i></b> - [IN] is the file path to a null-terminated string (with maximum string length of @endhtmlonly @ref CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH @htmlonly</li>
 *       <br />
 *       <li><b><i>oflag</i></b> - [IN] is the bitwise-inclusive OR of @endhtmlonly @ref connector_file_open_flags "file open flags" @htmlonly</li>
 *       <br />
 *       <li><b><i>handle</i></b> - [OUT] Application defined file handle</li>
 *     </ul>
 *   </td>
 * </tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>File opened successfully</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 * 
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_open(connector_file_system_open_t * const data) 
 * {
 *    connector_callback_status_t status = connector_callback_continue;
 *    int oflag = 0; 
 *    long int fd;
 *
 *    if (data->oflag & CONNECTOR_FILE_O_RDONLY) oflag |= O_RDONLY;
 *    if (data->oflag & CONNECTOR_FILE_O_WRONLY) oflag |= O_WRONLY;
 *    if (data->oflag & CONNECTOR_FILE_O_RDWR)   oflag |= O_RDWR;
 *    if (data->oflag & CONNECTOR_FILE_O_APPEND) oflag |= O_APPEND;
 *    if (data->oflag & CONNECTOR_FILE_O_CREAT)  oflag |= O_CREAT;
 *    if (data->oflag & CONNECTOR_FILE_O_TRUNC)  oflag |= O_TRUNC;
 *
 *    // 0664 = read,write owner + read,write group + read others
 *    fd = open(data->path, oflag, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH); 
 *
 *    if (fd >= 0)
 *    {
 *          data->handle = (void *) fd;
 *    }
 *    else 
 *    {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *    }
 *
 *    return status;
 * }
 * @endcode
 * <br />
 * 
 * @section file_system_lseek   Seek file position
 *
 * Set the offset for an open file.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_lseek @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_lseek_t "connector_file_system_lseek_t" @htmlonly structure where:
 *   <ul>
 *       <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *       <br /> 
 *       <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *       <br /> 
 *       <li><b><i>handle</i></b> - [IN] File handle</li>
 *       <br />
 *       <li><b><i>origin</i></b> - [IN] @endhtmlonly @ref connector_file_system_seek_cur, @htmlonly
 *                                   @endhtmlonly @ref connector_file_system_seek_set, @htmlonly
 *                                   or @endhtmlonly @ref connector_file_system_seek_end @htmlonly
 *                              </li>
 *       <br />
 *       <li><b><i>requested_offset</i></b> - [IN] Requested file offset</li>
 *       <br />
 *       <li><b><i>resulting_offset</i></b> - [OUT] Resulting file offset</li>
 *   </ul>
 * </td>
 * </tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>File offset set successfully</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly 
 * <br />
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_lseek(connector_file_system_lseek_t * const data) 
 * {
 *    connector_callback_status_t status = connector_callback_continue;
 *    int origin;
 *    off_t offset;
 *
 *    switch (data->origin)
 *    {
 *        case connector_file_system_seek_set:
 *           origin = SEEK_SET;
 *           break;
 *        case connector_file_system_seek_end:
 *           origin = SEEK_END;
 *           break;
 *        case connector_file_system_seek_cur:
 *        default:
 *           origin = SEEK_CUR;
 *           break;
 *    }
 *
 *    offset = lseek((long int) data->handle, data->requested_offset, origin);
 *
 *    data->resulting_offset = (connector_file_offset_t) offset;
 *
 *    if (offset < 0)
 *    {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *    }
 *    return status;
 * }
 *
 * @endcode
 * <br />
 *
 * @section file_system_read    Read file data
 *
 * Read data from an open file.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_read @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_read_t "connector_file_system_read_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>handle</i></b> - [IN] File handle</li>
 *      <br />
 *      <li><b><i>buffer</i></b> - Pointer to memory buffer where the callback places data retrieved from the file</li>
 *      <br />
 *      <li><b><i>bytes_available</i></b> - [IN] Size of the memory buffer</li>
 *      <br />
 *      <li><b><i>bytes_used</i></b> - [OUT] Number of bytes retrieved from the file and placed in the memory buffer</li>
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Reading from a file succeded</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br /> 
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_read(connector_file_system_read_t * const data) 
 * {
 *    connector_callback_status_t status = connector_callback_continue;
 * 
 *    int result = read((long int) data->handle, data->buffer, data->bytes_available);
 *
 *    if (result >= 0)
 *    {
 *        data->bytes_used = result;
 *    }
 *    else
 *    {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *    }
 *    return status;
 * } 
 *
 * @endcode
 * <br />  
 *
 * @section file_system_write   Write file data
 *
 * Write data to an open file.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_write @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_write_t "connector_file_system_write_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>handle</i></b> - [IN] File handle</li>
 *      <br />
 *      <li><b><i>buffer</i></b> - [IN] Pointer to data to write to the file</li>
 *      <br />
 *      <li><b><i>bytes_available</i></b> - [IN] Number of data bytes to to write to the file</li>
 *      <br />
 *      <li><b><i>bytes_used</i></b> - [OUT] Number of data bytes actually written to the file</li>
 *   </ul>
 * </td>
 * </tr>  
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Writing to a file succeded</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly 
 * <br />  
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_write(connector_file_system_write_t * const data) 
 * {
 *    connector_callback_status_t status = connector_callback_continue;
 * 
 *    int result = write((long int) data->handle, data->buffer, data->bytes_available);
 * 
 *    if (result >= 0)
 *    {
 *        data->bytes_used = result;
 *    }
 *    else
 *    {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *    }
 *    return status;
 * } 
 *
 * @endcode
 * <br />  
 *
 * @section file_system_truncate   Truncate a file
 *
 *
 * Truncate an open file to a specified length.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_ftruncate @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_truncate_t "connector_file_system_truncate_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>handle</i></b> - [IN] File handle</li>
 *      <br />
 *      <li><b><i>length_in_bytes</i></b> - [IN] Length in bytes to truncate a file to</li>
 *   </ul>
 * </td>
 * </tr>  
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>File truncated successfully</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly 
 * <br />
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_ftruncate(connector_file_system_truncate_t * const data) 
 * {
 *    connector_callback_status_t status = connector_callback_continue;
 * 
 *    int result = ftruncate((long int) data->handle, data->length_in_bytes);
 * 
 *    if (result < 0)
 *    {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *    }
 *
 *    return status;
 * } 
 *
 * @endcode
 * <br /> 
 *
 * @section file_system_close   Close a file
 *
 * Close an open file.
 *
 * @note This callback must release all resources, used during the file system session.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_close @htmlonly</td>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_close_t "connector_file_system_close_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>handle</i></b> - [IN] File handle</li>
 *   </ul>
 * </td>
 * </tr>  
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>File closed successfully</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly 
 * <br />
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_close(connector_file_system_close_t * const data) 
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 * 
 *     int result = close((long int) data->handle);
 *
 *     if (result < 0 && errno == EIO)
 *     {
 *        data->errnum = (void *) errno;
 *        status = connector_callback_error;
 *     }
 * 
 *     return status;
 *  } 
 *
 * @endcode
 * <br /> 
 *
 * @section file_system_remove      Remove a file
 *
 * Remove a file for the specified path. 
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_remove @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_remove_t "connector_file_system_remove_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *   <li><b><i>path</i></b> - [IN] File path is a null-terminated string.
 *                          See @endhtmlonly @ref CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH @htmlonly.</li>
 *   </ul>
 * </td>
 * </tr>   
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>File removed successfully</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br /> 
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_remove(connector_file_system_remove_t * const data)
 * {
 *    connector_callback_status_t status = connector_callback_continue;
 *
 *     // Posix function to remove a file
 *     int result = unlink(data->path);
 *
 *    if (result < 0)
 *    {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *    }
 *
 *    return status;
 * } 
 *
 * @endcode
 * <br /> 
 *
 * @section file_system_opendir     Open a directory
 *
 * Open a directory for the spesified path.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_opendir @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_opendir_t "connector_file_system_opendir_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>path</i></b> - [IN] Path is a null-terminated string.
 *                          See @endhtmlonly @ref CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH @htmlonly</li>
 *      <br />
 *      <li><b><i>handle</i></b> - [OUT] Application defined directory handle</li></ul>
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Directory opened successfully</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 * 
 * Example:
 *
 * @code
 *
 * typedef struct
 * {
 *    DIR         * dirp;
 *    struct dirent dir_entry;
 * 
 * } app_dir_data_t;
 *
 * connector_callback_status_t app_process_file_opendir(connector_file_system_opendir_t * const data)
 * {
 * 
 *     connector_callback_status_t status = connector_callback_continue;
 *     DIR * dirp;
 * 
 *     errno = 0;
 *     dirp = opendir(data->path);
 * 
 *     if (dirp != NULL)
 *     {
 *         void * ptr;
 *         app_dir_data_t * dir_data = malloc(sizeof *dir_data);
 *
 *         if (dir_data != NULL)
 *         {
 *             data->handle = dir_data;
 *             dir_data->dirp = dirp;
 *         }
 *         else
 *         {
 *             closedir(dirp);
 *             data->errnum = (void *) ENOMEM;
 *             status = connector_callback_error; 
 *         }
 *     }
 *     else
 *     {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *     }
 *     return status;
 * }
 *
 * @endcode
 * <br />
 * 
 * @section file_system_readdir     Read next directory entry
 *
 * The callbacks reads the next directory entry for the directory handle,
 * returned in the @ref file_system_opendir "open a directory" callback. 
 *
 * The callback writes the directory entry name at the entry_name pointer. When no more 
 * directory entries exist, the callback writes an empty string "".
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_readdir @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_readdir_t "connector_file_system_readdir_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>handle</i></b> - [IN] Directory handle</li>
 *      <br /> 
 *      <li><b><i>entry_name</i></b> - [OUT] Pointer to memory where the callback writes the directory entry name,
 *                                      a null-terminated string.</li> 
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Next directory entry returned or no more directory entries exist</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 * 
 * Example:
 *
 * @code
 *
 * typedef struct
 * {
 *    DIR         * dirp;
 *    struct dirent dir_entry;
 * 
 * } app_dir_data_t;
 *
 *
 * connector_callback_status_t app_process_file_readdir(connector_file_system_readdir_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *     app_dir_data_t * dir_data = data->handle;
 *     struct dirent  * result;
 *     int rc;
 * 
 *     // This sample does not skip "." and ".."
 * 
 *     rc = readdir_r(dir_data->dirp, &dir_data->dir_entry, &result);
 * 
 *     if (rc != 0)
 *     {
 *         // error
 *        if (rc == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) rc;
 *              status = connector_callback_error;
 *        }
 *     }
 *     else
 *     if (result == NULL)
 *     {
 *         // finished with the directory
 *         data->entry_name[0] = '\0';
 *     }
 *     else
 *     {
 *         // valid entry
 *         size_t name_len = strlen(result->d_name);
 * 
 *         if(name_len < data->bytes_available)
 *         {
 *             memcpy(data->entry_name, result->d_name, name_len + 1);
 *         }
 *         else
 *         {
 *             data->errnum = (void *) ENAMETOOLONG;
 *             status = connector_callback_error;
 *         }
 *     }
 *     return status;
 * }
 *
 * @endcode
 * <br />
 
 * @section file_system_closedir    Close a directory
 *
 * Close a directory for the directory handle, returned in the @ref file_system_opendir "open a directory"
 * callback.
 *
 * @note This callback must release all resources, used during the file system session.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_closedir @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_close_t "connector_file_system_close_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>handle</i></b> - [IN] Directory handle</li>
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Directory closed successfully</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 * Example:
 *
 * @code
 *
 * typedef struct
 * {
 *    DIR         * dirp;
 *    struct dirent dir_entry;
 * 
 * } app_dir_data_t;
 *
 *
 * connector_callback_status_t app_process_file_closedir(connector_file_system_close_t * const data)
 * {
 *     app_dir_data_t * dir_data = data->handle;
 *
 *     closedir(dir_data->dirp);
 *     free(dir_data);
 *
 *     // All session resources must be released in this callback
 *     return connector_callback_continue;
 * }
 * 
 * @endcode
 * <br /> 
 *
 * @section file_system_stat        Get file status
 *
 * Get file status for the named file path, received in a request from Device Cloud.
 * <br /><br /> 
 *
 * When called for a file, the callback returns the following information: 
 * @li File size
 * @li Last modified time
 * @li The @ref connector_file_system_file_type_is_reg flag set, if the path represents a regular file.
 * @li @ref connector_file_system_hash_algorithm_t "Hash algorithm" to be used for this file in a future
 * @ref file_system_hash "get file hash value" callback.
 *
 * When called for a directory, the callback returns the following information: 
 * @li Last modified time
 * @li The @ref connector_file_system_file_type_is_dir flag set.
 * @li @ref connector_file_system_hash_algorithm_t "Hash algorithm" to be used for each regular file in this directory
 * in a separate @ref file_system_hash "get file hash value" callback. 
 * <br /><br />
 *
 * Hash values support is optional.
 *
 * The following table shows the valid response for a requested hash algorithm:
 *
 * @htmlonly
 * <table class="apitable">
 * <tr>
 * <th class="title">Requested hash algorithm</th>
 * <th class="title">Actual hash algorithm</th>
 * </tr>
 * <tr>
 * <th> @endhtmlonly @ref connector_file_system_hash_best @htmlonly</th>
 * <td> @endhtmlonly @ref connector_file_system_hash_md5, @ref connector_file_system_hash_crc32,
 *                                           or @ref connector_file_system_hash_none @htmlonly </td>
 * </tr>
 * <tr>
 * <th> @endhtmlonly @ref connector_file_system_hash_md5 @htmlonly</th>
 * <td> @endhtmlonly @ref connector_file_system_hash_md5 or @ref connector_file_system_hash_none @htmlonly</td>
 * </tr>
 * <tr>
 * <th> @endhtmlonly @ref connector_file_system_hash_crc32 @htmlonly</th>
 * <td> @endhtmlonly @ref connector_file_system_hash_crc32 or @ref connector_file_system_hash_none @htmlonly</td>
 * </tr>
 * <tr>
 * <th> @endhtmlonly @ref connector_file_system_hash_none @htmlonly</th>
 * <td> @endhtmlonly @ref connector_file_system_hash_none @htmlonly</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br /><br />
 *
 * Callback arguments:
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_stat @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_stat_t "connector_file_system_stat_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>path</i></b> - [IN] Path is a null-terminated string.
 *                          See @endhtmlonly @ref CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH @htmlonly</li>
 *      <br /> 
 *      <li><b><i>statbuf</i></b> - [OUT] @endhtmlonly @ref connector_file_system_statbuf_t "Status data" @htmlonly</li>
 *      <br />
 *      <li><b><i>hash_algorithm.requested</i></b> - [IN] @endhtmlonly @ref connector_file_system_hash_algorithm_t
 *                                                       "Requested hash algorithm" @htmlonly</li>
 *      <br /> 
 *      <li><b><i>hash_algorithm.actual</i></b> - [OUT] @endhtmlonly @ref connector_file_system_hash_algorithm_t
 *                                                     "Actual hash algorithm" @htmlonly</li>
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Status information returned</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_stat(connector_file_system_stat_t * const data)
 * {
 *     struct stat statbuf;
 *     connector_callback_status_t status = connector_callback_continue;
 * 
 *     int result = stat(data->path, &statbuf);
 * 
 *     if (result == 0)
 *     {
 *         data->statbuf.flags         = connector_file_system_file_type_none;
 *         data->statbuf.last_modified = (uint32_t) statbuf.st_mtime;
 * 
 *         if (S_ISDIR(statbuf.st_mode))
 *            data->statbuf.flags = connector_file_system_file_type_is_dir;
 *         else
 *         if (S_ISREG(statbuf.st_mode))
 *         {
 *            data->statbuf.flags = connector_file_system_file_type_is_reg;
 *            data->statbuf.file_size     = (connector_file_offset_t) statbuf.st_size;
 *         }
 *
 *         data->hash_algorithm.actual  = connector_file_system_hash_none;
 *     }
 *     else
 *     {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *     }
 *     return status;
 * }
 *
 * @endcode
 * <br />
 *
 * @section file_system_stat_dir_entry  Get directory entry status
 *
 * Get status for the directory entry.
 * <br /><br />
 *
 * When called for a file, the callback returns the following information:
 * @li File size
 * @li Last modified time
 * @li The @ref connector_file_system_file_type_is_reg flag set, if the path represents a regular file.
 *
 * When called for a directory, the callback returns the following information: 
 * @li Last modified time
 * @li The @ref connector_file_system_file_type_is_dir flag set.
 * <br /><br />
 *
 * Callback arguments:
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_stat @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_stat_dir_entry_t "connector_file_system_stat_dir_entry_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>path</i></b> - [IN] Path is a null-terminated string.
 *                          See @endhtmlonly @ref CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH @htmlonly</li>
 *      <br /> 
 *      <li><b><i>statbuf</i></b> - [OUT] @endhtmlonly @ref connector_file_system_statbuf_t "Status data" @htmlonly</li>
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Status information returned</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_stat_dir_entry(connector_file_system_stat_dir_entry_t * const data)
 * {
 *     struct stat statbuf;
 *     connector_callback_status_t status = connector_callback_continue;
 * 
 *     int result = stat(data->path, &statbuf);
 * 
 *     if (result == 0)
 *     {
 *         data->statbuf.flags         = connector_file_system_file_type_none;
 *         data->statbuf.last_modified = (uint32_t) statbuf.st_mtime;
 * 
 *         if (S_ISDIR(statbuf.st_mode))
 *            data->statbuf.flags = connector_file_system_file_type_is_dir;
 *         else
 *         if (S_ISREG(statbuf.st_mode))
 *         {
 *            data->statbuf.flags = connector_file_system_file_type_is_reg;
 *            data->statbuf.file_size     = (connector_file_offset_t) statbuf.st_size;
 *         }
 *     }
 *     else
 *     {
 *        if (errno == EAGAIN)
 *        {
 *              status = connector_callback_busy;
 *        }
 *        else
 *        {
 *              data->errnum = (void *) errno;
 *              status = connector_callback_error;
 *        }
 *     }
 *     return status;
 * }
 *
 * @endcode
 * <br />
 *
 * @section file_system_hash        Get file hash value
 * 
 * Get a file hash value for the specified path.
 * <br /><br />
 *
 * Supported hash algorithms are md5 and crc32.
 *
 * An application callback might need more than one pass to calculate the hash value.
 * It can use user_context to point to intermidiate data and return
 * @ref connector_callback_busy. The callback will be repeated until it completes hash
 * calculations and returns @ref connector_callback_continue.
 *
 * If this callback has a problem reading a file, when called for a directory entry,
 * returns @ref connector_callback_error, the session will terminate without
 * sending any data for other directory entries. It's recommended to return @ref connector_callback_continue
 * to avoid this problem (the hash value will be zero).
 * <br /><br />
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_hash @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_hash_t "connector_file_system_hash_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [OUT] Callback sets this application-defined error token in case of I/O error to be used later in
 *                  @endhtmlonly @ref file_system_get_error "get error description" @htmlonly callback</li>
 *      <br /> 
 *      <li><b><i>path</i></b> - [IN] Path is a null-terminated string.
 *                          See @endhtmlonly @ref CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH @htmlonly</li>
 *      <br /> 
 *      <li><b><i>hash_algorithm</i></b> - [IN] @endhtmlonly @ref connector_file_system_hash_md5 or
 *                                              @ref connector_file_system_hash_crc32 @htmlonly</li>
 *      <br /> 
 *      <li><b><i>hash_value</i></b> - buffer where the callback writes the hash value</li>
 *      <br /> 
 *      <li><b><i>bytes_requested</i></b> - [IN] size of hash value in bytes, 16 bytes for md5,
 *                                          4 bytes for crc32.</li>
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Hash value returned</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_busy @htmlonly</td>
 * <td>Busy. The callback will be repeated
 * </td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_error @htmlonly</td>
 * <td>An error has occured
 * </td>
 * </tr> 
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_hash(connector_file_system_hash_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *
 *     switch (data->hash_algorithm)
 *     {
 *          case connector_file_hash_crc32:
 *              status = app_calc_crc32(data->path, data->hash_value);
 *              break;
 *
 *          case connector_file_hash_md5:
 *              status = app_calc_md5(data->path, data->hash_value);
 *              break;
 *     }
 *     return status;
 * }
 *
 * @endcode
 * <br /> 
 *
 * @section file_system_get_error    Get error description
 *
 * Get an error status code and an error description string to send to Etherios Device Cloud.
 * <br /><br />  
 *
 * Etherios Cloud Connector invokes this this callback if an earlier callback has returned
 * @ref connector_callback_error.
 *
 * Etherios Cloud Connector invokes this callback after calling the @ref file_system_close "close a file" 
 * or the @ref file_system_closedir "close a directory" callback.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_get_error @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> pointer to @endhtmlonly @ref connector_file_system_get_error_t "connector_file_system_get_error_t" @htmlonly structure where:
 *   <ul>
 *      <li><b><i>user_context</i></b> - [IN/OUT] Application-owned pointer</li>
 *      <br /> 
 *      <li><b><i>errnum</i></b> - [IN] Application-defined error token set in a previous callback</li>
 *      <br />
 *      <li><b><i>error_status</i></b> - [OUT] @endhtmlonly @ref connector_file_system_error_t "Error status code" @htmlonly</li>
 *      <br />
 *      <li><b><i>buffer</i></b> - Pointer to memory buffer where the callback writes an error description.
 *                                 The error description is not a null-terminated string </li>
 *      <br /> 
 *      <li><b><i>bytes_available</i></b> - [IN] Size of memory buffer in bytes</li>
 *      <br /> 
 *      <li><b><i>bytes_used</i></b> - [OUT] Number of description bytes written to the buffer</li>
 *   </ul>
 * </td>
 * </tr> 
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Returned error status and description</td>
 * </tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_abort @htmlonly</td>
 * <td>Callback aborted Etherios Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * <br />
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_get_error(connector_file_system_get_error_t * const data)
 * {
 *   long int errnum = (long int) data->errnum;
 *
 *   if (errnum != NULL)
 *   {
 *       char * err_str = strerror(errnum);
 *
 *       data->bytes_used = APP_MIN_VALUE(strlen(err_str), data->bytes_available);
 *       memcpy(data->buffer, err_str, data->bytes_used);
 *   }
 *
 *   switch(errnum)
 *   {
 *       case EACCES:
 *       case EPERM:
 *       case EROFS:
 *           data->error_status = connector_file_system_permision_denied;
 *           break;
 *
 *       case ENOMEM:
 *       case ENAMETOOLONG:
 *           data->error_status = connector_file_system_out_of_memory;
 *           break;
 *
 *       case ENOENT:
 *       case ENODEV:
 *       case EBADF:
 *           data->error_status = connector_file_system_path_not_found;
 *           break;
 *
 *       case EINVAL:
 *       case ENOSYS:
 *       case ENOTDIR:
 *       case EISDIR:
 *           data->error_status = connector_file_system_invalid_parameter;
 *           break;
 *
 *       case ENOSPC:
 *           data->error_status = connector_file_system_insufficient_storage_space;
 *           break;
 *
 *       default:
 *           data->error_status = connector_file_system_unspec_error;
 *           break;
 *   }
 *
 *   return connector_callback_continue;
 * }
 *
 * @endcode
 * <br /> 
 *
 * @section file_system_session_error   Inform of an Etherios Cloud Connector error
 *
 * An error in a file system session might be caused by network communication problems,
 * session timeout, insufficient memory, etc.
 *
 * Etherios Cloud Connector will invoke the @ref file_system_close "connector_request_id_file_system_close" 
 * or the @ref file_system_closedir "connector_request_id_file_system_closedir" callback after this callback.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr> 
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>class_id</td>
 * <td>@endhtmlonly @ref connector_class_id_file_system @htmlonly</td>
 * </tr>
 * <tr>
 * <td>request_id</td>
 * <td>@endhtmlonly @ref connector_request_id_file_system_session_error @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_data</th>
 * <td> [IN] pointer to @endhtmlonly @ref connector_file_error_request_t "connector_file_error_request_t" @htmlonly structure:
 *   <ul><li><b><i>message_status</i></b> - @endhtmlonly @ref connector_msg_error_t @htmlonly.</li></ul>
 * </td></tr>
 * <tr>
 * <td>request_length</td>
 * <td> [IN] Size of @endhtmlonly @ref connector_file_error_request_t "connector_file_error_request_t" @htmlonly structure</td>
 * </tr>
 * <tr>
 * <th>response_data</th>
 * <td> [IN] pointer to @endhtmlonly @ref connector_file_response_t "connector_file_response_t" @htmlonly structure:
 *   <ul><li><b><i>user_context</i></b> - Set by a user in an earlier callback.</li>
 *   <li><b><i>error</i></b> - Pointer to a @endhtmlonly @ref connector_file_error_data_t "connector_file_error_data_t" @htmlonly structure.</li></ul>
 * </td></tr>
 * <tr>
 * <td>response_length</td>
 * <td>[OUT] Size of @endhtmlonly @ref connector_file_response_t "connector_file_response_t" @htmlonly structure</td>
 * </tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr> 
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Continue</td>
 * </tr>
 * </table>
 * @endhtmlonly
 * 
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_file_msg_error(connector_file_error_request_t const * const request_data, 
 *                                                    connector_file_response_t * response_data)
 * {
 *     UNUSED_ARGUMENT(response_data);
 *
 *     APP_DEBUG("Message Error %d\n", request_data->message_status);
 *
 *    // All session resources must be released in this callback
 *    return connector_callback_continue;
 * }
 *
 * @endcode
 *
 * @htmlinclude terminate.html
 */
