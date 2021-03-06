#if (defined DOCUMENT_LEGACY_COMMANDS)
/*! @page rci_service Remote Configuration with legacy commands support
 *
 * @htmlinclude nav.html
 *
 * @section rci_overview Remote Configuration with legacy commands support Overview
 *
 * Remote configuration is an optional service for applications to
 * exchange device configuration data and information between the device and Device Cloud using
 * remote command interface (RCI).
 * User must define all device configurations that are accessed by Device Cloud and run the @ref rci_tool
 * to generate a source and header files for remote configuration support.
 *
 * Cloud Connector invokes the application-defined callbacks to configure and retrieve information from the device.
 *
 *  -# @ref rci_cancel
 *  -# @ref rci_session_start
 *  -# @ref rci_action_start
 *  -# @ref rci_group_start
 *  -# @ref rci_group_set
 *  -# @ref rci_group_query
 *  -# @ref rci_group_end
 *  -# @ref rci_action_end
 *  -# @ref rci_session_end
 *  -# @ref rci_session_cancel
 *
 * For legacy commands support, @ref rci_tool must be invoked using the '-rci_legacy_commands' option. Then Cloud Connector 
 * can invoke additionally following application-defined callbacks:
 *
 *  -# @ref rci_do_command
 *  -# @ref rci_reboot
 *  -# @ref rci_set_factory_def
 *
 *
 * The sequence calling an application-defined callback for remote configuration is:
 *  -# Cloud Connector calls application-defined @ref rci_session_start callback to start remote configuration request.
 *  -# Cloud Connector calls application-defined @ref rci_action_start callback to start setting or querying remote configuration.
 *  -# Cloud Connector calls application-defined @ref rci_group_start callback to start each configuration group.
 *  -# Cloud Connector calls application-defined:
 *      -# @ref rci_group_set callback number of times, until
 *      all the requested elements or data items of the configuration group are processed.
 *      -# @ref rci_group_query callback number of times, until
 *      all the requested elements or data items of the configuration group are retrieved.
 *  -# Cloud Connector calls application-defined @ref rci_group_end callback after all requested elements
 *     of the configuration group are processed.
 *  -# Cloud Connector calls application-defined @ref rci_action_end callback when it's done setting or querying all requested
 *     configuration groups.
 *  -# Cloud Connector calls application-defined @ref rci_session_end callback to end remote configuration request.
 *
 *
 * @note Cloud Connector calls step 3 to 5 repeatedly for each configuration group.
 * @note The request from the Cloud may include several actions for a single session, then Cloud Connector calls step 2 to 6 repeatedly for each action.
 * @note See @ref rci_support under Configuration to enable or disable remote configuration.
 * @note See RCI tool for generating remote configuration source and header files.
 * @note If remote configuration file specifies IPv4 type (see @ref rci_tool), @ref connector_snprintf must be implemented. See @ref snprintf_routine.
 *
 * The sequence calling an application-defined callback for a remote configuration legacy command is:
 *  -# Cloud Connector calls application-defined @ref rci_session_start callback to start remote configuration request session.
 *  -# Cloud Connector calls application-defined @ref rci_action_start callback to start the command.
 *  -# Cloud Connector calls the legacy command application-defined callback:
 *      -# @ref rci_do_command 
 *      -# @ref rci_reboot 
 *      -# @ref rci_set_factory_def 
 *  -# Cloud Connector calls application-defined @ref rci_action_end callback to end the command.
 *  -# Cloud Connector calls application-defined @ref rci_session_end callback to end remote configuration request session.
 *
 *
 * @note The request from the Cloud may include several actions (commands) for a single session, then Cloud Connector calls step 2 to 4 repeatedly for each action (command).
 * @note See @ref rci_support under Configuration to enable or disable remote configuration.
 * @note See RCI tool for generating remote configuration source and header files.
 *
 * @section rci_cancel Termination and Error Processing
 * The application-defined callback sets <b><i>error_id</i></b> field in the
 * @ref connector_remote_config_t "remote configuration response" structure
 * to make Cloud Connector send an error response to Device Cloud.
 * If Cloud Connector encounters error, it calls application-defined @ref rci_session_cancel callback
 * to cancel remote configuration request.
 *
 * All application memory must be released in the last callback, @ref rci_session_end
 * or @ref rci_session_cancel callbacks. When the callback returns an error, the callback must also
 * release all memory.
 *
 *
 * @section rci_session_start Start remote configuration session
 *
 * This callback is called to start remote configuration request session.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_session_start @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Callback writes its own context which will be passed back to
 *                subsequent callback.</dd>
 *         <dt><i>action</i></dt><dd>Not applicable</dd>
 *         <dt><i>attribute</i></dt><dd>Not applicable</dd>
 *         <dt><i>group</i></dt><dd>Not applicable</dd>
 *         <dt><i>element</i></dt><dd>Not applicable</dd>
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                     error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback successfully started remote configuration or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 *
 * static connector_callback_status_t app_process_session_start(connector_remote_config_t * const data)
 * {
 *     void * ptr;
 *     remote_group_session_t * session_ptr;
 *
 *     printf("process_session_start\n");
 *
 *     if (malloc(sizeof *session_ptr, &ptr) == NULL)
 *     {
 *         data->error_id = connector_global_error_no_memory;
 *         data->response.error_hint = NULL;
 *         goto done;
 *     }
 *
 *     session_ptr = ptr;
 *     session_ptr->group_context = NULL;
 *
 * done:
 *     data->user_context = ptr;
 *     return connector_callback_continue;
 * }
 * @endcode
 *
 *
 * @section rci_action_start    Start remote configuration action
 *
 * This callback is called to start remote configuration request action
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_action_start @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                Callback may write its own context which will be passed back to
 *                subsequent callback.</dd>
 *         <dt><i>action</i></dt>
 *         <dd> <ul><li>@endhtmlonly @ref connector_remote_action_set @htmlonly to set device configurations or </li>
 *                  <li>@endhtmlonly @ref connector_remote_action_query @htmlonly to query device configurations.</li>
 *                  <li>@endhtmlonly @ref connector_remote_action_do_command @htmlonly to process a do_command command.</li>
 *                  <li>@endhtmlonly @ref connector_remote_action_reboot @htmlonly to process a reboot command.</li>
 *                  <li>@endhtmlonly @ref connector_remote_action_set_factory_def @htmlonly to process a set_factory_default command.</li>
 *         </ul></dd>
 *
 *         <dt><i>attribute</i></dt>
 *         <dd>- Following attributes only applicable when action is@endhtmlonly @ref connector_remote_action_query and group.type is @ref connector_remote_group_setting.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>source</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_source_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         <dd><dl>
 *             <dt><i>compare_to</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_none @htmlonly: No difference requested. Return all values as specified in source.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         <dd>- Following attribute only applicable when action is@endhtmlonly @ref connector_remote_action_do_command.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>target</i></dt>
 *             <dd>String containing the do_command target attribute </dd>
 *         </dl></dd>
 *         </dl></dd>
 *
 *         <dt><i>group</i></dt>
 *         <dd><dl>
 *             <dt><i>type</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref connector_remote_group_setting @htmlonly for setting configuration group or </li>
 *                      <li>@endhtmlonly @ref connector_remote_group_state @htmlonly for state configuration group.</li></ul></dd>
 *             <dt><i>id</i></dt><dd> - not applicable.</dd>
 *             <dt><i>index</i></dt><dd> - not applicable.</dd>
 *         </dl></dd>
 *
 *         <dt><i>element</i></dt> <dd>- not applicable.</dd>
 *
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback successfully started setting or querying remote configuration or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 *
 * static connector_callback_status_t app_process_action_start(connector_remote_config_t * const data)
 * {
 *     printf("process_action_start\n");
 *
 *     return connector_callback_continue;
 * }
 *
 * @endcode
 *
 * @section rci_group_start   Start a configuration group
 *
 * Callback is called to start processing each configuration group
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_group_start @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                 Callback may write its own context which will be passed back to
 *                 subsequent callback.</dd>
 *
 *         <dt><i>action</i></dt>
 *         <dd> <ul><li>@endhtmlonly @ref connector_remote_action_set @htmlonly to set device configurations or </li>
 *                  <li>@endhtmlonly @ref connector_remote_action_query @htmlonly to query device configurations.</li></ul></dd>
 *
 *         <dt><i>attribute</i></dt>
 *         <dd>- Following attributes only applicable when action is@endhtmlonly @ref connector_remote_action_query and group.type is @ref connector_remote_group_setting.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>source</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_source_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         <dd><dl>
 *             <dt><i>compare_to</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_none @htmlonly: No difference requested. Return all values as specified in source.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         </dl></dd>
 *
 *         <dt><i>group</i></dt>
 *         <dd><dl>
 *             <dt><i>type</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref connector_remote_group_setting @htmlonly for setting configuration group or </li>
 *                      <li>@endhtmlonly @ref connector_remote_group_state @htmlonly for state configuration group.</li></ul></dd>
 *
 *             <dt><i>id</i></dt><dd> - the group configuration enumeration number
 *                                          (generated by @endhtmlonly @ref rci_tool @htmlonly) to be accessed.</dd>
 *             <dt><i>index</i></dt><dd> - the index number of the configuration group.</dd>
 *         </dl> </dd>
 *
 *         <dt><i>element</i></dt> <dd> not applicable.</dd>
 *
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by  @endhtmlonly @ref rci_tool @htmlonly if
 *                error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt>
 *             <dd> - If the following conditions are met:</dd>
 *                    <dd><ul><li>action is @endhtmlonly @ref connector_remote_action_query.@htmlonly</li>
 *                          <li>group.type is @endhtmlonly @ref connector_remote_group_setting.@htmlonly</li>
 *                          <li>attribute.compare_to is different than @endhtmlonly @ref rci_query_setting_attribute_compare_to_none.@htmlonly</li></ul></dd> 
 *                    <dd>&nbsp;&nbsp;this field can be set to 'connector_true' to inform the Cloud Connector that there is no need to transmit a value to Device Cloud. 
 *                    Cloud Connector won't call the elements callback for the group and will skip the group in the response.</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback successfully started processing a configuration group or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 * static connector_callback_status_t app_process_group_init(connector_remote_config_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *     remote_group_table_t * group_ptr = NULL;
 *     remote_config_session_t * session_ptr = data->user_context;
 *
 *     ASSERT(session_ptr != NULL);
 *
 *     printf("process_group_init\n");
 *
 *     switch (data->group.type)
 *     {
 *     case connector_remote_group_setting:
 *         if (data->group.id <= sizeof (remote_setting_table))
 *         {
 *             group_ptr = &remote_setting_table[data->group.id];
 *             session_ptr->group = group_ptr;
 *         }
 *         else
 *         {
 *             ASSERT(0);
 *         }
 *         break;
 *     case connector_remote_group_state:
 *         ASSERT(0);
 *         break;
 *     }
 *
 *     if (group_ptr->init_cb)
 *     {
 *         status = group_ptr->init_cb(data);
 *     }
 *
 *     return status;
 * }
 *
 * @endcode
 *
 * @section rci_group_set   Set a configuration element
 *
 * Callback is called to set an element in a configuration group
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_group_process @htmlonly</td>
 * </tr>
 * <tr>
 *   <th>data</th>
 *   <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                     Callback may write its own context which will be passed back to
 *                     subsequent callback.</dd>
 *         <dt><i>action</i></dt>
 *         <dd> - @endhtmlonly @ref connector_remote_action_set @htmlonly.</dd>
 *         <dt><i>attribute</i></dt><dd>Not applicable</dd>
 *         <dt><i>group</i></dt>
 *         <dd><dl>
 *             <dt><i>type</i></dt>
 *             <dd><ul>
 *                <li>@endhtmlonly @ref connector_remote_group_setting @htmlonly for setting configuration group or </li>
 *                <li>@endhtmlonly @ref connector_remote_group_state @htmlonly for state configuration group.</li>
 *             </ul></dd>
 *
 *             <dt><i>id</i></dt>
 *             <dd> configuration group enumeration number
 *                 (generated by @endhtmlonly @ref rci_tool @htmlonly) to be accessed.</dd>
 *
 *             <dt><i>index</i></dt>
 *             <dd> - the index number of the configuration group.</dd>
 *         </dl></dd>
 *
 *         <dt><i>element</i></dt>
 *         <dd><dl>
 *             <dt><i>id</i></dt>
 *             <dd> - the element enumeration number (generated by @endhtmlonly @ref rci_tool @htmlonly)
 *                                           of the configuration group to be set.</dd>
 *             <dt><i>type</i></dt>
 *             <dd> - the value type of the element. See
 *                   @endhtmlonly connector_element_value_type_t @htmlonly for list of element types</dd>
 *             <dt><i>value</i></dt>
 *             <dd> - Pointer to @endhtmlonly connector_element_value_t @htmlonly
 *                    which contains the element value to be set:
 *
 *                 <dl><dt><i>string_value</i></dt>
 *                 <dd> - contains a NULL-terminated data string for the following types:
 *                    <ul>
 *                      <li>@endhtmlonly @ref connector_element_type_string @htmlonly</li>
 *                      <li>@endhtmlonly @ref connector_element_type_multiline_string @htmlonly</li>
 *                      <li>@endhtmlonly @ref connector_element_type_password @htmlonly</li>
 *                      <li>@endhtmlonly @ref connector_element_type_ipv4 @htmlonly</li>
 *                      <li>@endhtmlonly @ref connector_element_type_fqdnv4 @htmlonly</li>
 *                      <li>@endhtmlonly @ref connector_element_type_fqdnv6 @htmlonly</li>
 *                      <li>@endhtmlonly @ref connector_element_type_mac_addr @htmlonly</li>
 *                      <li>@endhtmlonly @ref connector_element_type_datetime @htmlonly</li>
 *                 </ul></dd>
 *
 *                 <dt><i>integer_signed_value</i></dt>
 *                 <dd> - contains a signed integer number for @endhtmlonly @ref connector_element_type_int32 @htmlonly type. </dd>
 *
 *                 <dt><i>integer_unsigned_value</i></dt>
 *                 <dd> - contains an unsigned integer number for the following types:
 *                    <ul>
 *                      <li>@endhtmlonly @ref connector_element_type_uint32 @htmlonly </li>
 *                      <li>@endhtmlonly @ref connector_element_type_hex32 @htmlonly </li>
 *                      <li>@endhtmlonly @ref connector_element_type_0x_hex32 @htmlonly </li>
 *                 </ul></dd>
 *
 *                 <dt><i>float_value</i></dt>
 *                 <dd> - contains a floating point value for @endhtmlonly @ref connector_element_type_float @htmlonly type.</dd>
 *
 *                 <dt><i>enum_value</i></dt>
 *                 <dd> - contains an enumeration value (generated by the RCI tool) for
 *                         @endhtmlonly @ref connector_element_type_enum @htmlonly type. </dd>
 *
 *                 <dt><i>on_off_value</i></dt>
 *                 <dd> - contains <b> @endhtmlonly @ref connector_on @htmlonly</b> or <b> @endhtmlonly @ref connector_off @htmlonly </b> value for
 *                         @endhtmlonly @ref connector_element_type_on_off @htmlonly type.</dd>
 *
 *                 <dt><i>boolean_value</i></dt>
 *                 <dd> - contains <b> @endhtmlonly @ref connector_true @htmlonly </b> or <b> @endhtmlonly @ref connector_false @htmlonly </b> value
 *                     for @endhtmlonly @ref connector_element_type_boolean @htmlonly type.</dd>
 *
 *                 </dl>
 *             </dd>
 *         </dl></dd>
 *
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                     error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback successfully set an element of the configuration group or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 * static connector_callback_status_t app_process_group_set(connector_remote_config_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *     remote_config_session_t * session_ptr = data->user_context;
 *     keepalive_data_t * const keepalive_ptr;
 *
 *     printf("process_group_set\n");
 *
 *     keepalive_ptr = session_ptr->group_context;
 *
 *     switch (data->element.id)
 *     {
 *     case connector_setting_keepalive_rx:
 *         keepalive_ptr->rx_keepalive_current = data->element.value->integer_unsigned_value;
 *         break;
 *     case connector_setting_keepalive_tx:
 *         keepalive_ptr->tx_keepalive_current = data->element.value->integer_unsigned_value;
 *         break;
 *     default:
 *         break;
 *     }
 *     return status;
 * }
 * @endcode
 *
 * @section rci_group_query   Query a configuration element
 *
 * Callback is called to query an element in a configuration group.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_group_process @htmlonly</td>
 * </tr>
 * <tr>
 *   <th>data</th>
 *   <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                Callback may write its own context which will be passed back to
 *                 subsequent callback.</dd>
 *
 *         <dt><i>action</i></dt>
 *         <dd> - @endhtmlonly @ref connector_remote_action_query @htmlonly.</dd>
 *
 *         <dt><i>attribute</i></dt>
 *         <dd>- Following attributes only applicable when action is@endhtmlonly @ref connector_remote_action_query and group.type is @ref connector_remote_group_setting.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>source</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_source_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         <dd><dl>
 *             <dt><i>compare_to</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_none @htmlonly: No difference requested. Return all values as specified in source.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         </dl></dd>
 *
 *         <dt><i>group</i></dt>
 *         <dd><dl>
 *             <dt><i>type</i></dt>
 *             <dd><ul>
 *                <li>@endhtmlonly @ref connector_remote_group_setting @htmlonly for setting configuration group or </li>
 *                <li>@endhtmlonly @ref connector_remote_group_state @htmlonly for state configuration group.</li>
 *             </ul></dd>
 *
 *             <dt><i>id</i></dt>
 *             <dd> configuration group enumeration number
 *                 (generated by @endhtmlonly @ref rci_tool @htmlonly) to be accessed.</dd>
 *
 *             <dt><i>index</i></dt>
 *             <dd> - the index number of the configuration group.</dd>
 *         </dl></dd>
 *
 *        <dt><i>element</i></dt>
 *        <dd><dl>
 *            <dt><i>id</i></dt>
 *            <dd> - the element enumeration number (generated by @endhtmlonly @ref rci_tool @htmlonly)
 *                                           of the configuration group to be queried.</dd>
 *            <dt><i>type</i></dt>
 *            <dd> - the value type of the element. See
 *                   @endhtmlonly @ref connector_element_value_type_t @htmlonly </dd>
 *            <dt><i>value</i></dt>
 *            <dd> - Not applicable </dd>
 *         </dl></dd>
 *
 *        <dt><i>error_id</i></dt>
 *        <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                     error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *
 *        <dt><i>response</i></dt>
 *        <dd><dl> Callback writes compare_matches to skip response for the element, error hint if error is encountered or the value of the element.
 *             <dt><i>compare_matches</i></dt>
 *             <dd> - If the following conditions are met:</dd>
 *                    <dd><ul><li>group.type is @endhtmlonly @ref connector_remote_group_setting.@htmlonly</li>
 *                          <li>attribute.compare_to is different than @endhtmlonly @ref rci_query_setting_attribute_compare_to_none.@htmlonly</li></ul></dd> 
 *                    <dd>&nbsp;&nbsp;this field can be set to 'connector_true' to inform the Cloud Connector that there is no need to transmit a value to Device Cloud. 
 *                    Cloud Connector will skip the element in the response.</dd>
 *            <dt><i>error_hint</i></dt>
 *            <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                         which will be sent to Device Cloud if error is encountered.
 *                         This string cannot be altered until next callback call.
 *                         Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *
 *            <dt><i>element_value</i></dt>
 *            <dd> - Pointer to @endhtmlonly @ref connector_element_value_t @htmlonly
 *                           which callback returns the value of the requested element:
 *                 <dl><dt><i>string_value</i></dt>
 *                     <dd> - Callback returns a pointer to a NULL-terminated data string for the following types:
 *                        <ul>
 *                          <li>@endhtmlonly @ref connector_element_type_string @htmlonly</li>
 *                          <li>@endhtmlonly @ref connector_element_type_multiline_string @htmlonly</li>
 *                          <li>@endhtmlonly @ref connector_element_type_password @htmlonly</li>
 *                          <li>@endhtmlonly @ref connector_element_type_ipv4 @htmlonly</li>
 *                          <li>@endhtmlonly @ref connector_element_type_fqdnv4 @htmlonly</li>
 *                          <li>@endhtmlonly @ref connector_element_type_fqdnv6 @htmlonly</li>
 *                          <li>@endhtmlonly @ref connector_element_type_mac_addr @htmlonly</li>
 *                          <li>@endhtmlonly @ref connector_element_type_datetime @htmlonly</li>
 *                        </ul>
 *                     </dd>
 *
 *                     <dt><i>integer_signed_value</i></dt>
 *                     <dd> - Callback writes a signed integer number for @endhtmlonly @ref connector_element_type_int32 @htmlonly type. </dd>
 *
 *                     <dt><i>integer_unsigned_value</i></dt>
 *                     <dd> - Callback writes an unsigned integer number for the following types:
 *                        <ul>
 *                          <li>@endhtmlonly @ref connector_element_type_uint32 @htmlonly </li>
 *                          <li>@endhtmlonly @ref connector_element_type_hex32 @htmlonly </li>
 *                          <li>@endhtmlonly @ref connector_element_type_0x_hex32 @htmlonly </li>
 *                        </ul>
 *                     </dd>
 *
 *                     <dt><i>float_value</i></dt>
 *                     <dd> - Callback writes a floating point value for @endhtmlonly @ref connector_element_type_float @htmlonly type.</dd>
 *
 *                     <dt><i>enum_value</i></dt>
 *                     <dd> - Callback writes an enumeration value (generated by the RCI tool) for
 *                             @endhtmlonly @ref connector_element_type_enum @htmlonly type. </dd>
 *
 *                     <dt><i>on_off_value</i></dt>
 *                     <dd> - Callback writes <b> @endhtmlonly @ref connector_on @htmlonly </b> or <b> @endhtmlonly @ref connector_off @htmlonly </b> value for
 *                            @endhtmlonly @ref connector_element_type_on_off @htmlonly type.</dd>
 *
 *                     <dt><i>boolean_value</i></dt>
 *                     <dd> - Callback writes <b> @endhtmlonly @ref connector_true @htmlonly </b> or <b> @endhtmlonly @ref connector_false @htmlonly </b> value
 *                              for @endhtmlonly @ref connector_element_type_boolean @htmlonly type.</dd>
 *                 </dl>
 *            </dd></dl>
 *        </dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback successfully retrieved an element's value or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 * static connector_callback_status_t app_process_group_get(connector_remote_config_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *     remote_config_session_t * session_ptr = data->user_context;
 *     keepalive_data_t * keepalive_ptr;
 *     connector_bool_t const comparing_with_defaults = data->attribute.source == rci_query_setting_attribute_source_current && 
 *                                                      data->attribute.compare_to == rci_query_setting_attribute_compare_to_defaults;
 *
 *     printf("process_group_get\n");
 *
 *     keepalive_ptr = session_ptr->group_context;
 *
 *     switch (data->element.id)
 *     {
 *     case connector_setting_keepalive_rx:
 *
 *         // Skip reporting this element if Cloud is asking to compare current with defaults and value has not changed
 *         if (comparing_with_defaults && keepalive->rx_keepalive_current == keepalive->rx_keepalive_default)
 *         {
 *             data->response.compare_matches = connector_true;
 *         }
 *         else
 *         {
 *             data->response.element_value->integer_unsigned_value = keepalive->rx_keepalive_current;
 *         }
 *         break;
 *     case connector_setting_keepalive_tx:
 *
 *         // Skip reporting this element if Cloud is asking to compare current with defaults and value has not changed
 *         if (comparing_with_defaults && keepalive->tx_keepalive_current == keepalive->tx_keepalive_default)
 *         {
 *             data->response.compare_matches = connector_true;
 *         }
 *         else
 *         {
 *             data->response.element_value->integer_unsigned_value = keepalive->tx_keepalive_current;
 *         }
 *         break;
 *     default:
 *         break;
 *     }
 *
 *     return status;
 * }
 * @endcode
 *
 * @section rci_group_end   End of a configuration group
 *
 * Callback is called indicating Cloud Connector is done processing a configuration group.
 * Callback may start writing the configuration onto NvRAM or flash in a separated thread.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_group_end @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                 Callback may write its own context which will be passed back to
 *                 subsequent callback.</dd>
 *
 *         <dt><i>action</i></dt>
 *         <dd> <ul><li>@endhtmlonly @ref connector_remote_action_set @htmlonly to set device configurations or </li>
 *                  <li>@endhtmlonly @ref connector_remote_action_query @htmlonly to query device configurations.</li></ul></dd>
 *
 *         <dt><i>attribute</i></dt>
 *         <dd>- Following attributes only applicable when action is@endhtmlonly @ref connector_remote_action_query and group.type is @ref connector_remote_group_setting.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>source</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_source_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         <dd><dl>
 *             <dt><i>compare_to</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_none @htmlonly: No difference requested. Return all values as specified in source.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         </dl></dd>
 *
 *         <dt><i>group</i></dt>
 *         <dd><dl>
 *             <dt><i>type</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref connector_remote_group_setting @htmlonly for setting configuration group or </li>
 *                      <li>@endhtmlonly @ref connector_remote_group_state @htmlonly for state configuration group.</li></ul></dd>
 *
 *             <dt><i>id</i></dt><dd> - the group configuration enumeration number
 *                                          (generated by @endhtmlonly @ref rci_tool @htmlonly) to be accessed.</dd>
 *             <dt><i>index</i></dt><dd> - the index number of the configuration group.</dd>
 *         </dl> </dd>
 *
 *         <dt><i>element</i></dt> <dd> not applicable.</dd>
 *
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by  @endhtmlonly @ref rci_tool @htmlonly if
 *                error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback was successfully done processing the configuration group or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_busy @htmlonly</th>
 * <td>Busy and callback will be called again</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 * static connector_callback_status_t app_process_group_end(connector_remote_config_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *     remote_config_session_t * session_ptr = data->user_context;
 *     keepalive_data_t * keepalive_ptr;
 *
 *     printf("process_group_end\n");
 *
 *     keepalive_ptr = session_ptr->group_context;
 *
 *     // should start writing onto NvRAM
 *     nvRamKeepalive = *keepalive_ptr;
 *     flashWrite(nvRamKeepalive);
 *     return status;
 * }
 *
 * @endcode
 *
 * @section rci_action_end   End of remote configuration action
 *
 * Callback is called indicating Cloud Connector is done with the action. When setting or querying device configuration,
 * callback may start writing device configurations onto NvRAM or flash in a separated thread.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_action_end @htmlonly</td>
 * </tr>
 * <tr>
  * <th>data</th>
 * <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                Callback may write its own context which will be passed back to
 *                subsequent callback.</dd>
 *         <dt><i>action</i></dt>
 *         <dd> <ul><li>@endhtmlonly @ref connector_remote_action_set @htmlonly to set device configurations or </li>
 *                  <li>@endhtmlonly @ref connector_remote_action_query @htmlonly to query device configurations.</li>
 *                  <li>@endhtmlonly @ref connector_remote_action_do_command @htmlonly to process a do_command command.</li>
 *                  <li>@endhtmlonly @ref connector_remote_action_reboot @htmlonly to process a reboot command.</li>
 *                  <li>@endhtmlonly @ref connector_remote_action_set_factory_def @htmlonly to process a set_factory_default command.</li>
 *         </ul></dd>
 *         <dt><i>attribute</i></dt>
 *         <dd>- Following attributes only applicable when action is@endhtmlonly @ref connector_remote_action_query and group.type is @ref connector_remote_group_setting.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>source</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_source_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_source_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         <dd><dl>
 *             <dt><i>compare_to</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_none @htmlonly: No difference requested. Return all values as specified in source.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_current @htmlonly: The current running settings.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_stored @htmlonly: The configuration stored persistently. This is the configuration that will be used by the device if it is rebooted.</li>
 *                      <li>@endhtmlonly @ref rci_query_setting_attribute_compare_to_defaults @htmlonly: The default configuration of the device. This is the configuration that will be used if 'set_factory_default' is issued.</li></ul></dd>
 *         </dl></dd>
 *         <dd>- Following attribute only applicable when action is@endhtmlonly @ref connector_remote_action_do_command.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>target</i></dt>
 *             <dd>String containing the do_command target attribute </dd>
 *         </dl></dd>
 *         </dl></dd>
 *
 *         <dt><i>group</i></dt>
 *         <dd><dl>
 *             <dt><i>type</i></dt>
 *             <dd> <ul><li>@endhtmlonly @ref connector_remote_group_setting @htmlonly for setting configuration group or </li>
 *                      <li>@endhtmlonly @ref connector_remote_group_state @htmlonly for state configuration group.</li></ul></dd>
 *             <dt><i>id</i></dt><dd> - not applicable.</dd>
 *             <dt><i>index</i></dt><dd> - not applicable.</dd>
 *         </dl></dd>
 *
 *         <dt><i>element</i></dt> <dd>- not applicable.</dd>
 *
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>@endhtmlonly @ref connector_callback_continue @htmlonly</td>
 * <td>Callback was successfully done setting or queryingremote configuration or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_busy @htmlonly</th>
 * <td>Busy and callback will be called again</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 * static connector_callback_status_t app_process_action_end(connector_remote_config_t_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *
 *     printf("process_action_end\n");
 *
 *     if (!isFlashWriteDone(nvRamKeepalive))
 *     {
 *        status = connector_callback_busy;
 *     }
 *     return status;
 * }
 * @endcode
 *
 * @section rci_session_end   End of remote configuration session
 *
 * Notify callback to end remote configuration session.
 * Callback must release its own memory used for this remote configuration request.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_session_end @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.</dd>
 *         <dt><i>action</i></dt><dd>Not applicable</dd>
 *         <dt><i>attribute</i></dt><dd>Not applicable</dd>
 *         <dt><i>group</i></dt><dd>Not applicable</dd>
 *         <dt><i>element</i></dt><dd>Not applicable</dd>
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                     error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback was successfully done remote configuration request or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_busy @htmlonly</th>
 * <td>Busy and callback will be called again</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 * static connector_callback_status_t app_process_session_end(connector_remote_config_t * const data)
 * {
 *     printf("process_session_end\n");
 *     if (data->user_context != NULL)
 *     {
 *         free(data->user_context);
 *     }
 *     return connector_callback_continue;
 * }
 *
 * @endcode
 *
 * @section rci_session_cancel   Cancel remote configuration
 *
 * Callback is called to cancel remote configuration.
 * Callback must release its own memory used for the remote configuration request.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_session_cancel @htmlonly</td>
 * </tr>
 * <tr>
 * <th>data</th>
 * <td> Pointer to  @endhtmlonly @ref connector_remote_config_cancel_t @htmlonly
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Callback's context from previous callback.</dd>
 * </td>
 * </tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <td>No return value</td>
 * <td>N/A</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 * static void app_process_session_cancel(connector_remote_config_cancel_t * const data)
 * {
 *     ASSERT(data->user_context != NULL);
 *
 *     printf("app_process_session_cancel\n");
 *
 *     free(data->user_context);
 *
 * }
 *
 * @endcode
 *
 * @section rci_do_command   Process a do_command command
 *
 * Callback is called to process a do_command command.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_do_command @htmlonly</td>
 * </tr>
 * <tr>
 *   <th>data</th>
 *   <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                     Callback may write its own context which will be passed back to
 *                     subsequent callback.</dd>
 *         <dt><i>action</i></dt>
 *         <dd> - @endhtmlonly @ref connector_remote_action_do_command @htmlonly.</dd>
 *
 *         <dt><i>attribute</i></dt>
 *         <dd>- Following attribute only applicable when action is@endhtmlonly @ref connector_remote_action_do_command.@htmlonly</dd>
 *         <dd><dl>
 *             <dt><i>target</i></dt>
 *             <dd>String containing the do_command target attribute </dd>
 *         </dl></dd>
 *         </dl></dd>
 *
 *         <dt><i>group</i></dt><dd>Not applicable</dd>
 *
 *         <dt><i>element</i></dt>
 *         <dd><dl>
 *             <dt><i>id</i></dt>
 *             <dd> - Not applicable.</dd>
 *             <dt><i>type</i></dt>
 *             <dd> - Not applicable</dd>
 *             <dt><i>value->string_value</i></dt>
 *             <dd> - Contains a NULL-terminated string with the do_command request payload.</dd>
 *         </dl></dd>
 *
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                     error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value->string_value</i></dt>
 *            <dd> - Pointer to string (allocated by the user) where callback returns the do_command response payload</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback processed do_command command successfully or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_do_command(connector_remote_config_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 *     remote_group_session_t * const session_ptr = (remote_group_session_t *)data->user_context;
 *     char const * target = data->attribute.target;
 *     char const * const request_payload = data->element.value->string_value;
 *     char const * * response_payload = &data->response.element_value->string_value;
 * 
 *     if (target != NULL)
 *     {
 *         APP_DEBUG("app_process_do_command for target '%s':\n", target);
 *     }
 *     else
 *     {
 *         APP_DEBUG("app_process_do_command with no target\n");
 *         *response_payload = "no target";
 *         goto done;
 *     }
 * 
 *     if (request_payload != NULL)
 *     {
 *         APP_DEBUG("request_payload len=%d\n", strlen(request_payload));
 *         APP_DEBUG("request_payload='%s'\n", request_payload);
 *     }
 *     else
 *     {
 *         APP_DEBUG("no payload!\n");
 *     }
 * 
 *     if (!strcmp(target, "echo"))
 *     {
 *         char * my_answer = malloc(strlen(request_payload) + 1);
 *         strcpy(my_answer, request_payload);
 * 
 *         // Update session so buffer is freed in the session_end callback
 *         session_ptr->buf_ptr = my_answer;
 *         *response_payload = my_answer;
 *     }
 *     else if (!strcmp(target, "ping"))
 *     {
 *         *response_payload = "pong";
 *     }
 *     else if (!strcmp(target, "no answer"))
 *     {
 *     }
 *     else if (!strcmp(target, "error"))
 *     {
 *         data->error_id = connector_global_error_do_command_fail;
 *         data->response.error_hint = "do command intentional failure";
 *     }
 *     else if (!strcmp(target, "busy"))
 *     {
 *         static int i = 0;
 * 
 *         if (i++ < 2) 
 *         {
 *             status = connector_callback_busy;
 *         }
 *         else
 *         {
 *             *response_payload = "I returned busy twice";
 *         }
 *     }
 *     else if (!strcmp(target, "malloc"))
 *     {
 *         #define ALLOCATED_MEM_SIZE 5000
 * 
 *         char * allocated_mem = malloc(ALLOCATED_MEM_SIZE + 1);
 * 
 *         if (allocated_mem != NULL)
 *         {
 *             memset(allocated_mem, '-', ALLOCATED_MEM_SIZE);
 * 
 *             allocated_mem[ALLOCATED_MEM_SIZE] = '\0';
 * 
 *             // Update session so buffer is freed in the session_end callback
 *             session_ptr->buf_ptr = allocated_mem;
 * 
 *             *response_payload = allocated_mem;
 *         }
 *     }
 *     else
 *     {
 *         *response_payload = "not supported command";
 *     }
 * 
 * done:
 *     return status;
 * }
 * @endcode
 *
 * @section rci_reboot   Process a reboot command
 *
 * Callback is called to process a reboot command.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_reboot @htmlonly</td>
 * </tr>
 * <tr>
 *   <th>data</th>
 *   <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                     Callback may write its own context which will be passed back to
 *                     subsequent callback.</dd>
 *         <dt><i>action</i></dt>
 *         <dd> - @endhtmlonly @ref connector_remote_action_reboot @htmlonly.</dd>
 *
 *         <dt><i>attribute</i></dt><dd>Not applicable</dd>
 *         <dt><i>group</i></dt><dd>Not applicable</dd>
 *         <dt><i>element</i></dt><dd>Not applicable</dd>
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                     error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value->string_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback processed reboot command successfully or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_reboot(connector_remote_config_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 * 
 *    APP_DEBUG("app_process_reboot\n");
 *
 *     if (do_not_want_to_reboot())
 *     {
 *         data->error_id = connector_global_error_reboot_fail;
 *         data->response.error_hint = "don't want to reboot";
 *     }
 *     else
 *     {
 *          APP_DEBUG("app_process_reboot: The system will be rebooted!\n");
 *     }
 * 
 *     return status;
 * }
 * @endcode
 *
 * @section rci_set_factory_def   Process a set_factory_default command
 *
 * Callback is called to process a set_factory_default command.
 *
 * @htmlonly
 * <table class="apitable">
 * <tr> <th colspan="2" class="title">Arguments</th> </tr>
 * <tr><th class="subtitle">Name</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>class_id</th>
 * <td>@endhtmlonly @ref connector_class_id_remote_config @htmlonly</td>
 * </tr>
 * <tr>
 * <th>request_id</th>
 * <td>@endhtmlonly @ref connector_request_id_remote_config_set_factory_def @htmlonly</td>
 * </tr>
 * <tr>
 *   <th>data</th>
 *   <td> Pointer to @endhtmlonly connector_remote_config_t @htmlonly structure:
 *     <dl><dt><i>user_context</i></dt>
 *         <dd> - Pointer to callback's context returned from previous callback.
 *                     Callback may write its own context which will be passed back to
 *                     subsequent callback.</dd>
 *         <dt><i>action</i></dt>
 *         <dd> - @endhtmlonly @ref connector_remote_action_set_factory_def @htmlonly.</dd>
 *
 *         <dt><i>attribute</i></dt><dd>Not applicable</dd>
 *         <dt><i>group</i></dt><dd>Not applicable</dd>
 *         <dt><i>element</i></dt><dd>Not applicable</dd>
 *         <dt><i>error_id</i></dt>
 *         <dd> - Callback writes error enumeration value generated by @endhtmlonly @ref rci_tool @htmlonly if
 *                     error is encountered. Cloud Connector sends error description if it's provided for the given error_id.</dd>
 *         <dt><i>response</i></dt>
 *         <dd><dl>
 *             <dt><i>compare_matches</i></dt><dd>Not applicable</dd>
 *             <dt><i>error_hint</i></dt>
 *             <dd> - Callback returns a pointer to a constant null-terminated hint string
 *                    which will be sent to Device Cloud if error is encountered.
 *                    This string cannot be altered until next callback call.
 *                    Note: This must be set to NULL for no hint string when error_id is set.</dd>
 *             <dt><i>element_value->string_value</i></dt><dd>Not applicable</dd>
 *         </dl></dd>
 *     </dl>
 * </td></tr>
 * <tr> <th colspan="2" class="title">Return Values</th> </tr>
 * <tr><th class="subtitle">Values</th> <th class="subtitle">Description</th></tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_continue @htmlonly</th>
 * <td>Callback processed set_factory_default command successfully or error has occurred</td>
 * </tr>
 * <tr>
 * <th>@endhtmlonly @ref connector_callback_abort @htmlonly</th>
 * <td>Callback aborted Cloud Connector</td>
 * </tr>
 * </table>
 * @endhtmlonly
 *
 * Example:
 *
 * @code
 *
 * connector_callback_status_t app_process_set_factory_default(connector_remote_config_t * const data)
 * {
 *     connector_callback_status_t status = connector_callback_continue;
 * 
 *     APP_DEBUG("app_process_set_factory_default\n");
 * 
 *     if (my_set_factory_default_went_wrong())
 *     {
 *         data->error_id = connector_global_error_set_factory_default_fail;
 *         data->response.error_hint = "can't do that";
 *     }
 * 
 *     return status;
 * }
 * @endcode
 *
 * @htmlinclude terminate.html
 */
