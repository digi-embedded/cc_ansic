package com.digi.connector.config;

import java.io.BufferedWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.digi.connector.config.ConfigGenerator.FileType;

public class FileGlobalHeader extends FileGenerator {

    private static FileType fileType = FileType.GLOBAL_HEADER;
    
	public FileGlobalHeader(String directoryPath) throws IOException {
		
		super(directoryPath,HEADER_FILENAME,fileType);
        for (Element.ElementType type : Element.ElementType.values()) {
            type.set();
        }
	}
	
    public void writeHeaderComment(BufferedWriter bufferWriter) throws IOException {
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();

        String note_string = "/*\n * This is an auto-generated file - DO NOT EDIT! \n";

        note_string += String.format(" * This is a public header file generated by %s tool.\n", TOOL_NAME);

        
        note_string += String.format(" * This file was generated on: %s \n", dateFormat.format(date))
                     + String.format(" * The command line arguments were: %s\n", ConfigGenerator.getArgumentLogString())
                     + String.format(" * The version of %s tool was: %s */\n\n", TOOL_NAME, ConfigGenerator.VERSION);
        
        bufferWriter.write(note_string);
        
    }
    public void generateFile(ConfigData configData) throws Exception {
        try {

            String defineName = generatedFile.replace('.', '_').toLowerCase();

            fileWriter.write(String.format("#ifndef %s\n#define %s\n", defineName, defineName));
            fileWriter.write(CONNECTOR_GLOBAL_HEADER);
            fileWriter.write(CONNECTOR_CONST_PROTECTION);
            fileWriter.write("#define CONNECTOR_BINARY_RCI_SERVICE\n");

            writeDefinesAndStructures(configData);
            
            writeRciErrorEnumHeader(configData, fileWriter);
    
            fileWriter.write(CONNECTOR_CONST_PROTECTION_RESTORE);
            fileWriter.write(String.format("\n#endif\n"));
           
            ConfigGenerator.log(String.format("File created:\n\t%s%s",  filePath, generatedFile));

        } catch (IOException e) {
            throw new IOException(e.getMessage());
        }

        finally {
            fileWriter.close();
        }

    }


}