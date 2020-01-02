package afuc;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class AfucHeader implements StructConverter {
	private int version;
	private int tableOffset;
	
	public AfucHeader(BinaryReader reader) throws IOException {
		reader.readNextInt(); // zero, stripped by the kernel
		version = reader.readNextInt();
		tableOffset = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(DWORD, 4, "zero", null);
		structure.add(DWORD, 4, "version", null);
		structure.add(DWORD, 4, "table_offset", null);
		return structure;
	}
	
	public int getVersion() {
		/*
		 * From the a6xx firmware:
		 * 		and $05, $addr, 0xfff
		 * 		shl $05, 0x14
		 * 
		 * The shl is because the actual version is built out of this header version as
		 * well as other versions.
		 */
		return version & 0xfff;
	}

	public int getTableOffset() {
		/*
		 * From the a6xx firmware:
		 * 		rot $06, $addr, 0x8
		 * 		ushr $06, $06, 0x6
		 * 
		 * Add an extra 4 bytes for the zero field which is stripped off by the kernel.
		 */
		return (((tableOffset << 8) | (tableOffset >>> (32 - 8))) >>> 6) + 4;
	}
}
