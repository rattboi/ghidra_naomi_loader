/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package seganaomi;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SegaNaomiLoader extends AbstractLibrarySupportLoader {

	private static final long DEF_RAM_BASE = 0x8C000000L;
	private static final long RAM_SIZE = 0x02000000L;
	private static final String OPTION_NAME = "RAM Base Address: ";
	private static long ramBase = DEF_RAM_BASE;

	@Override
	public String getName() {
		return "Sega Naomi Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		String s = reader.readAsciiString(0, 16);

		if (s.equals("NAOMI")) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH4:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		FlatProgramAPI fpa = new FlatProgramAPI(program);

		getNaomiLoadEntries(fpa, provider, log);

		// createSegment(fpa, ramStream, "RAM", ramBase, RAM_SIZE, true, true, log);
	}

	private static void getNaomiLoadEntries(FlatProgramAPI fpa, ByteProvider provider, MessageLog log) {

		BinaryReader reader = new BinaryReader(provider, true);
		// jump to 0x360 (load entries)
		reader.setPointerIndex(0x360L);

		boolean moreEntries = true;
		int numEntries = 1;

		do {
			try {
				long romOffset	 = reader.readNextUnsignedInt();
				long ramAddress  = reader.readNextUnsignedInt();
				long entryLength = reader.readNextUnsignedInt();

				if (entryLength == 0 || entryLength == 0xFFFFFFFFL)  {
					moreEntries = false;
				} else {
					for (int i = 0; i < 8; i++) {
						long logicalRamAddress = (i << 29) | ramAddress;
						InputStream istream = reader.getByteProvider().getInputStream(romOffset);
						createSegment(fpa, istream, "Game Entry (" + numEntries + ")(" + i + ")", logicalRamAddress, entryLength, true, true, log);
					}
					numEntries++;
				}
			} catch (Exception e) {
				log.appendException(e);
			}
		} while (moreEntries == true);
	}

	private static void createNamedByte(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log) {
		Address addr = fpa.toAddr(address);

		try {
			fpa.createByte(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}

		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private static void createNamedWord(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log) {
		Address addr = fpa.toAddr(address);

		try {
			fpa.createWord(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}

		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private static void createNamedDword(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log) {
		Address addr = fpa.toAddr(address);

		try {
			fpa.createDWord(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}

		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private static void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
