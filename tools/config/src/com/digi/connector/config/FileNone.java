package com.digi.connector.config;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;

import com.digi.connector.config.ConfigGenerator.FileType;
import com.digi.connector.config.Element.ElementType;


public class FileNone extends FileGenerator {

	private static String COPYRIGHT = "/*\n"
			 +" * Copyright (c) 2013 Digi International Inc.,\n"
			 +" * All rights not expressly granted are reserved.\n"
			 +" *\n"
			 +" * This Source Code Form is subject to the terms of the Mozilla Public\n"
			 +" * License, v. 2.0. If a copy of the MPL was not distributed with this file,\n"
			 +" * You can obtain one at http://mozilla.org/MPL/2.0/.\n"
			 +" *\n"
			 +" * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343\n"
			 +" * =======================================================================\n"
			 +" */\n";

    protected final static String PRINTF = "    printf(\"    Called '%s'\\n\", __FUNCTION__);\n";
    protected final static String RETURN_CONTINUE = "    return connector_callback_continue;\n}\n";

    private static FileType fileType = FileType.NONE;
    private BufferedWriter functionWriter = null;
    private String functionFile = "";
    
	public FileNone(String directoryPath) throws IOException {
		
		super(directoryPath,HEADER_FILENAME,fileType);	
		functionFile = "remote_config_cb.c";
        functionWriter = new BufferedWriter(new FileWriter(filePath + functionFile));
        functionWriter.write(COPYRIGHT);

	}
    public void writeHeaderComment(BufferedWriter bufferWriter) throws IOException {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();

        String note_string = "/*\n * This is an auto-generated file - DO NOT EDIT! \n";
        
   
        note_string += String.format(" * This is generated by %s tool \n", TOOL_NAME);

        
        note_string += String.format(" * This file was generated on: %s \n", dateFormat.format(date))
                     + String.format(" * The command line arguments were: %s\n", ConfigGenerator.getArgumentLogString())
                     + String.format(" * The version of %s tool was: %s */\n\n", TOOL_NAME, ConfigGenerator.VERSION);
        
        bufferWriter.write(note_string);
        
    }
    public void generateFile(ConfigData configData) throws Exception {
        try {

            String defineName = generatedFile.replace('.', '_').toLowerCase();
                       
            fileWriter.write(String.format("#ifndef %s\n#define %s\n\n", defineName, defineName));
            fileWriter.write(CONNECTOR_GLOBAL_HEADER);
            fileWriter.write(CONNECTOR_CONST_PROTECTION);

            writeDefinesAndStructures(configData);
            
            /* Write all group enum in H file */
            writeRciErrorEnumHeader(configData, fileWriter);
            writeGlobalErrorEnumHeader(configData, fileWriter);

            writeGroupTypeAndErrorEnum(configData,fileWriter);

            writePrototypes(configData,fileWriter);

            fileWriter.write(CONNECTOR_CONST_PROTECTION_RESTORE);
            fileWriter.write(String.format("\n#endif\n"));
            
            /*Write function file */
            writeFunctionFile(configData, functionWriter);
            
                       
            ConfigGenerator.log(String.format("Files created:\n\t%s%s",  filePath, generatedFile));
            if (generatedFile.length() > 0) ConfigGenerator.log(String.format("\t%s%s", filePath, functionFile));

        } catch (IOException e) {
            throw new IOException(e.getMessage());
        }

        finally {
            fileWriter.close();
            functionWriter.close();
        }

    }
    
    private String UNUSED(String parameter) {
        return "UNUSED_PARAMETER(" + parameter + ");\n";
    }

    
    private void writeFunctionFile(ConfigData configData, BufferedWriter bufferWriter) throws Exception
    {
        bufferWriter.write(String.format("%s \"%s\"", INCLUDE, HEADER_FILENAME));
        bufferWriter.write(String.format("\n%s UNUSED_PARAMETER(a) (void)(a)\n",DEFINE));
        /*
         * Start writing:
         * 1. all #define for all strings from user's groups
         * 2. all #define for all RCI and user's global errors
         * 3. all strings in connector_remote_all_strings[]
         */
        bufferWriter.write("\n\n#define CONST const \n");

        bufferWriter.write(String.format("#define FIRMWARE_TARGET_ZERO_VERSION  0x%X\n\n",ConfigGenerator.getFirmware()));

        /* Write Define Errors Macros */
        writeDefineRciErrors(configData,bufferWriter);

        writeDefineGroupErrors(configData,bufferWriter);

        writeDefineGlobalErrors(configData,bufferWriter);

        /* write remote all strings in source file */
        writeRemoteAllStrings(configData,bufferWriter);

        /* write connector_rci_errors[] */
        writeGlobalErrorStructures(configData,bufferWriter);

        /* write structures in source file */
        writeAllStructures(configData,bufferWriter);

        bufferWriter.write(String.format("\nconnector_remote_config_data_t rci_desc_data = {\n" +
		"    connector_group_table,\n"+
		"    connector_rci_errors,\n"+
		"    connector_rci_error_COUNT,\n"+
		"    FIRMWARE_TARGET_ZERO_VERSION,\n"+
		"    %s,\n"+
		"    \"%s\"\n"+
		"};\n", Descriptors.vendorId(),Descriptors.deviceType()));

    	String session_function = setFunction("rci_session_start_cb(" + RCI_INFO_T + ")",null);
    	session_function += setFunction("rci_session_end_cb(" + RCI_INFO_T + ")",null);
        bufferWriter.write(session_function);
        for (GroupType type : GroupType.values()) {
	        LinkedList<Group> groups = null;

	        configType = type.toString().toLowerCase();
	        groups = configData.getConfigGroup(configType);

	        if (!groups.isEmpty()) {

	            for (Group group : groups) {
	                String group_function = setFunction(String.format("%srci_%s_%s_start(%s)",prefix,configType,group.getName(),RCI_INFO_T),null);
	                group_function += setFunction(String.format("%srci_%s_%s_end(%s)",prefix,configType,group.getName(),RCI_INFO_T),null);
	            	bufferWriter.write(group_function);
		            for (Element element : group.getElements()) {
		                String element_function ="";
		                String FType = "";
		                String value = "";
		                switch(ElementType.toElementType(element.getType())){
		                    case UINT32:
		                    	if(element.getMin()!=null)
		                    		value += "*value = " + element.getMin();
		                    	else
		                    		value += "*value = 123";
		                    	FType += "uint32_t";
		                        break;
		                    case HEX32:
		                    case X_HEX32:
		                    	value += "*value = 0x20101010";
		                    	FType += "uint32_t";
		                        break;
		                    case INT32:
		                    	if(element.getMin()!=null)
		                    		value += "*value = " + element.getMin();
		                    	else
		                    		value += "*value = 15";
		                    	FType += "int32_t";
		                        break;
		                    case FLOAT:
		                    	value += "*value = 1.2";
		                    	FType += "float";
		                        break;
		                    case ON_OFF:
		                    	value += "*value = connector_on";
		                    	FType += "connector_on_off_t";
		                        break;
		                    case ENUM:
		                        ValueStruct first_value = element.getValues().get(0);
		                        value += "*value = connector_" + configType + "_" + group.getName() + "_" + element.getName() + "_" + first_value.getName();
		                        FType += String.format("%sconnector_%s_%s_%s_id_t",prefix,configType,group.getName(),element.getName());
		                        break;
		                    case IPV4:
		                    case FQDNV4:
		                    case FQDNV6:
		                    	value += "*value = \"192.168.1.1\"";
		                    	FType += "char const *";
		                        break;
		                    case DATETIME:
		                    	value += "*value = \"2002-05-30T09:30:10-0600\";";
		                    	FType += "char const *";
		                        break;
		                    case STRING:
		                    case MULTILINE_STRING:
		                    	value += "*value = \"String\"";
		                    case PASSWORD:
		                    	FType += "char const *";
		                        break;
		                    case BOOLEAN:
		                    	value += "*value = connector_true";
		                    	FType += "connector_bool_t";
		                        break;
	                        default:
	                            break;
		                }
		                if(!(ElementType.toElementType(element.getType()).toValue() == 3/*PASSWORD*/)){
		                    element_function += setFunction(String.format("%srci_%s_%s_%s_get(%s, %s * const value)"
                                ,prefix,configType,group.getName(),element.getName(),RCI_INFO_T,FType),value);
		                }
		                if(!getAccess(element.getAccess()).equalsIgnoreCase("read_only")) {
		                    element_function += setFunction(String.format("%srci_%s_%s_%s_set(%s, %s const value)"
                                ,prefix,configType,group.getName(),element.getName(),RCI_INFO_T,FType),"UNUSED_PARAMETER(value)");
			            }
		            	bufferWriter.write(element_function);
		            }//No more elements
         
	            }//No more groups
	        }
        }//No more group types

    }

    private String setFunction (String parameter,String value){
    	String function = CONNECTOR_CALLBACK_STATUS + parameter + "\n{\n    ";
        function += UNUSED("info") + PRINTF;
        if(value != null){
        	function += "    " + value + ";\n";
        }
        function += RETURN_CONTINUE;
    	return  function;
    }

}
