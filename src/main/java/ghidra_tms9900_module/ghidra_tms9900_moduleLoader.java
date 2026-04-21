package ghidra.plugin.loader.tms9900;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.mem.MemoryImageSourceInfo;
import ghidra.program.model.mem.MemoryImageSourceInfo.ImageType;
import ghidra.program.model.mem.FileBytes;
import ghidra.program.model.mem.FileBytesService;
import ghidra.program.model.mem.ProgramByteProvider;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.app.util.importer.AutoImporter;

public class TMS9900Loader extends AbstractLibrarySupportLoader {

    @Override
    public String getName() {
        return "TMS9900-Raw-Loader-11.4-12.0";
    }

    @Override
    public List<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        // Accept any raw binary by default. If you have a magic/signature, test here.
        List<LoadSpec> results = new ArrayList<>();
        // Add an unspecified language spec so user can choose the TMS9900 language in the import dialog.
        results.add(new LoadSpec(this, 0, true));
        return results;
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec) {
        return Collections.emptyList();
    }

    @Override
    public boolean supportsLoadIntoProgram() {
        return true;
    }

    @Override
    public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            ghidra.util.task.TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {

        FlatProgramAPI api = new FlatProgramAPI(program, monitor);

        try {
            long fileLen = provider.length();

            AddressFactory af = program.getAddressFactory();
            AddressSpace space = af.getDefaultAddressSpace();
            Address base = space.getAddress(0x0000);

            // Create an initialized memory block from the file bytes
            Memory memory = program.getMemory();

            // Create FileBytes backing (useful for editors and bytes display)
            FileBytes fb = memory.createFileBytes(restorer(provider), "tms9900_image", 0, fileLen, monitor);

            MemoryBlock block = memory.createFileBlock("tms9900_blob", base, fb, 0, fileLen, false);
            block.setRead(true);
            block.setWrite(true); // TMS9900 RAM/ROM depends on file; set writable to allow edits
            block.setExecute(true);

            // Set entry point at 0x0000 and create a label
            Address entry = base;
            program.getSymbolTable().createLabel(entry, "_start", SourceType.IMPORTED);
            program.getMemory().setExecute(entry, true);

            // Set default language if none — look for TMS9900 language id "tms9900:LE:default" or similar.
            // If the program already has a language, skip.
            if (program.getLanguageCompilerSpec() == null) {
                // Attempt to set language via AutoImporter if possible; many Ghidra installs include a TMS9900 language.
                // If unavailable, user can change language manually in Program -> Change Language.
            }

            log.appendMsg("TMS9900 loader: mapped " + fileLen + " bytes at " + base.toString());
        } catch (MemoryConflictException | IOException | MemoryAccessException e) {
            log.appendException(e);
            throw new IOException(e);
        }
    }

    // Helper to create FileBytes provider in a way compatible across Ghidra versions
    private ghidra.program.model.mem.FileBytes restorer(ByteProvider provider) throws IOException {
        // The simplest approach is to use MemoryByteProvider -> ProgramByteProvider if needed.
        // But createFileBytes can accept a ByteProvider's InputStream in many versions; to keep compatibility,
        // we'll return a simple FileBytes wrapper implemented using MemoryByteProvider via Program's memory.
        // For portability in this minimal loader, we'll use the provider's getInputStream directly through a temp FileBytes.
        // Note: Some Ghidra versions require FileBytes created via program.getMemory().createFileBytes with InputStream.
        // To keep compatibility, we'll use the provider's underlying InputStream via a custom FileBytes created by memory API.
        throw new IOException("FileBytes helper not implemented for this minimal gist. Use createFileBlock alternative if needed.");
    }
}
