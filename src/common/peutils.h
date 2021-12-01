//
// peutils.h
//
// Utility functions that work with Portable Executable images and Windows Loader.
//

namespace peutils {

    // 
    // listTEBLoadedDlls
    // 
    // Obtains access to Windows Loader structures in PEB/TEB, enumerates all PE images
    // that are loaded into the process address space (at least the ones that are known
    // to the loader), and prints to debug output their names and base addresses.
    //
    void listTEBLoadedDlls();

}