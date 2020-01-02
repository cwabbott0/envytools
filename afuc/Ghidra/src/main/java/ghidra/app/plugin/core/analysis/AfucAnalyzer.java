package ghidra.app.plugin.core.analysis;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import afuc.AfucHeader;
import ghidra.app.services.*;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class AfucAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "afuc analyzer";
	private static final String DESCRIPTION = "Annotates jump table and imports register descriptions from rnndb";
	private static final String PROCESSOR_NAME = "adreno 5xx/6xx microcode";
	private static final int TABLE_SIZE = 0x80;
	private static final int INTERRUPT_IDX = 15;

	public static final Processor PROCESSOR = Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME);
	
	private int curVariant; // 5 for a5xx, 6 for a6xx

	public AfucAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor() == PROCESSOR;
	}
	
	private String getRnndbPath() {
		URL url = AfucAnalyzer.class.getProtectionDomain().getCodeSource().getLocation();
		try {
			String path = new File(url.toURI()).getCanonicalPath();
			System.out.println(path);
			return path + "/../../../../rnndb/";
		} catch (IOException | URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	private XmlPullParser getParser(String file) throws SAXException, IOException {
		ErrorHandler errHandler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(AfucAnalyzer.this, "Error parsing " + file, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(AfucAnalyzer.this, "Fatal error parsing " + file,
					exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(AfucAnalyzer.this, "Warning parsing " + file, exception);
			}
		};
		
		XmlPullParser parser = XmlPullParserFactory.create(new File(file), errHandler, false);
		return parser;
	}
	
	private int parseVariant(String variant) {
		return variant.charAt(1) - '0';
	}
	
	private boolean checkVariants(String variantStr) {
		if (variantStr.contains("-")) {
			// Assume this is a range like "A5XX-"
			String[] range = variantStr.split("-");
			String start = range[0];
			
			if (!start.equals("")) {
				if (parseVariant(start) > curVariant)
					return false;
			}
			if (range.length > 1 && !range[1].equals("")) {
				String end = range[1];
				if (parseVariant(end) < curVariant)
					return false;
			}
		} else {
			String[] variants = variantStr.split(",");
			for (String variant : variants) {
				if (parseVariant(variant) == curVariant)
					return true;
			}
			return false;
		}
		
		return false;
	}
	
	private HashMap<Integer, String> parseEnum(XmlPullParser parser) {
		HashMap<Integer, String> map = new HashMap<Integer, String>();
		XmlElement valueEnter;
		while ((valueEnter = parser.softStart("value", "doc")) != null) {
			if (valueEnter.getName() != "value" ||
					(valueEnter.hasAttribute("variants") && !checkVariants(valueEnter.getAttribute("variants")))) {
				while (!parser.peek().isEnd())
					parser.discardSubTree();
				parser.end(valueEnter);
				continue;
			}
			map.put(SpecXmlUtils.decodeInt(valueEnter.getAttribute("value")), valueEnter.getAttribute("name"));
			parser.end(valueEnter);
		}
		return map;
	}
	
	private HashMap<Integer, String> getPacketNames(XmlPullParser parser) {
		parser.start("database");
		
		XmlElement enumEnter;
		while ((enumEnter = parser.softStart("enum")) != null) {
			if (enumEnter.getAttribute("name").equals("adreno_pm4_type3_packets")) {
				return parseEnum(parser);
			}
			while (!parser.peek().isEnd())
				parser.discardSubTree();
			parser.end();
		}
		return null;
	}
	
	private HashMap<Integer, String> getControlRegs(XmlPullParser parser) {
		parser.start("database");
		
		XmlElement enumEnter;
		while ((enumEnter = parser.softStart("enum")) != null) {
			if (parseVariant(enumEnter.getAttribute("name").substring(0, 4)) == curVariant) {
				return parseEnum(parser);
			}
			while (!parser.peek().isEnd())
				parser.discardSubTree();
			parser.end();
		}
		return null;
	}

	private Data createData(Program program, Address address, DataType dt, MessageLog log) {
		try {
			Data d = program.getListing().getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
						ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
			return d;
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
		
		return null;
	}
	
	private Data createNamedData(Program program, Address address, String name, DataType dt, MessageLog log) {
		try {
			program.getSymbolTable().createLabel(address, name, SourceType.ANALYSIS);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
		
		return createData(program, address, dt, log);
	}
	
	private XmlElement skipDoc(XmlPullParser parser, XmlElement elem) {
		while (!elem.isEnd() && elem.getName().equals("doc")) {
			parser.discardSubTree(elem);
			elem = parser.next();
		}
		
		return elem;
	}
	
	private DataType getRegType(XmlPullParser parser, XmlElement elem) throws InvalidInputException {
		if (elem.getName().equals("reg32")) {
			parser.discardSubTree(elem);
			return DWordDataType.dataType;
		} else if (elem.getName().equals("reg64")) {
			parser.discardSubTree(elem);
			if (elem.getAttribute("type").equals("waddress")) {
				return new PointerDataType(null, 8);
			} else {
				return QWordDataType.dataType;
			}
		} else if (elem.getName().equals("array")) {
			// note: an array is actually an array of structs
			Structure structure = new StructureDataType(elem.getAttribute("name"), 4 * XmlUtils.decodeUnknownInt(elem.getAttribute("stride")));
			while (!parser.peek().isEnd()) {
				XmlElement header = parser.next();
				header = skipDoc(parser, header);
				DataType member = getRegType(parser, header);
				int offset = 4 * XmlUtils.decodeUnknownInt(header.getAttribute("offset"));
				for (int i = 0; i < member.getLength(); i += 4)
					structure.clearComponent(structure.getComponentAt(offset + i).getOrdinal());
				structure.replaceAtOffset(offset, member,
						member.getLength(), header.getAttribute("name"), null);
			}
			parser.end(elem);
			return new ArrayDataType(structure, XmlUtils.decodeUnknownInt(elem.getAttribute("length")), structure.getLength());
		}
		
		throw new InvalidInputException(String.format("unknown type %s", elem.getName()));
	}
	
	private void parseRegisters(Program program, XmlPullParser parser, MessageLog log) {
		parser.start("database");
		XmlElement header;
		while (!(header = parser.next()).isEnd()) {
			if (header.getName().equals("domain") &&
				header.getAttribute("name").equals("A" + Integer.toString(curVariant) + "XX")) {
				break;
			}
			
			parser.discardSubTree(header);
		}
		
		AddressSpace registers = program.getAddressFactory().getAddressSpace("gpu_register");
		
		try {
			while (!(header = parser.next()).isEnd()) {
				header = skipDoc(parser, header);
				if (header.getName().equals("bitset") ||
						header.getName().equals("enum")) {
					parser.discardSubTree(header);
					continue;
				}
				
				DataType type = getRegType(parser, header);
				int offset = XmlUtils.decodeUnknownInt(header.getAttribute("offset"));
				Address addr = registers.getAddress(offset * 4);
				createNamedData(program, addr, header.getAttribute("name"), type, log);
			}
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		curVariant = parseVariant(program.getLanguage().getLanguageDescription().getVariant());

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		BinaryReader reader = new BinaryReader(provider, true);
		
		try {
			AfucHeader header = new AfucHeader(reader);
			AddressSpace codeSpace = program.getAddressFactory().getDefaultAddressSpace();
			Address start = codeSpace.getAddress(0);
			createData(program, start, header.toDataType(), log);

			// Register initializer run at startup.
			Address initAddress = codeSpace.getAddress(reader.getPointerIndex());

			SymbolTable table = program.getSymbolTable();
			table.addExternalEntryPoint(initAddress);
			table.createLabel(initAddress, "afuc_init", SourceType.ANALYSIS);
			
			Address tableAddress = codeSpace.getAddress(header.getTableOffset());
			DataType dt = new ArrayDataType(DWordDataType.dataType, TABLE_SIZE, 4);
			createData(program, tableAddress, dt, log);
			
			String path = getRnndbPath();
			
			XmlPullParser packetParser = getParser(path + "adreno/adreno_pm4.xml");
			HashMap<Integer, String> packets = getPacketNames(packetParser);

			reader.setPointerIndex(header.getTableOffset());
			HashSet<Integer> knownOffsets = new HashSet<Integer>();
			for (int i = 0; i < TABLE_SIZE; i++) {
				// Add 4 for the zero field that's stripped by the kernel
				int offset = (reader.readNextInt() << 2) + 4;
				String name = packets.containsKey(i) ? packets.get(i) : ("UNKN" + Integer.toString(i));
				Address address = codeSpace.getAddress(offset);
				//table.addExternalEntryPoint(initAddress);
				if (!table.hasSymbol(address)) {
					table.createLabel(address, name, SourceType.ANALYSIS);
				}
				if (!knownOffsets.contains(offset)) {
					knownOffsets.add(offset);
					Function f = program.getFunctionManager().createFunction(name, address, new AddressSet(address), SourceType.ANALYSIS);
					if (i != INTERRUPT_IDX) {
						f.setCallingConvention("__pkt");
					}
				}
			}
			
			XmlPullParser controlParser = getParser(path + "adreno/adreno_config_regs.xml");
			HashMap<Integer, String> controlRegs = getControlRegs(controlParser);
			
			AddressSpace controlRegSpace = program.getAddressFactory().getAddressSpace("control_register");
			for (Map.Entry<Integer, String> entry : controlRegs.entrySet()) {
				String name = entry.getValue();
				int offset = entry.getKey();
				Address addr = controlRegSpace.getAddress(offset * 4);
				if (name.endsWith("_HI"))
					continue;
				
				DataType type = DWordDataType.dataType;
				if (name.endsWith("_LO")) {
					name = name.substring(0, name.length() - 3);
					type = QWordDataType.dataType;
				}
				
				createData(program, addr, type, log);
				table.createLabel(addr, name, SourceType.ANALYSIS);
			}
			
			XmlPullParser regParser = getParser(path + "adreno/a" + Integer.toString(curVariant) + "xx.xml");
			parseRegisters(program, regParser, log);
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
		return true;
	}
}
