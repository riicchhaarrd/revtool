// CLI tool for testing the decompiler without the GUI.
// Usage:
//   decomp <binary> [-l] [-F] [-f <hex_addr>] [-s <src_idx>] [-a]
//
//   -l           List source files
//   -F           List functions (with addresses)
//   -f <addr>    Decompile function at hex address
//   -s <idx>     Decompile source file by index
//   -a           Decompile all source files
//   -n <name>    Decompile function by name (substring match)
//   --gcc        Pipe output through gcc -fsyntax-only to count errors

#include "decompiler.h"
#include "macho.h"
#include <QCoreApplication>
#include <QProcess>
#include <cstdio>
#include <cstring>

static void listSourceFiles(const MachOFile &mf) {
    auto &sources = mf.stabsSourceFiles();
    for (size_t i = 0; i < sources.size(); ++i) {
        auto &sf = sources[i];
        printf("[%3zu] %s%s  (%zu functions)\n",
               i, sf.directory.c_str(), sf.filename.c_str(),
               sf.functionIndices.size());
    }
}

static void listFunctions(const MachOFile &mf) {
    auto &funcs = mf.stabsFunctions();
    auto &types = mf.typeTable();
    for (size_t i = 0; i < funcs.size(); ++i) {
        auto &fn = funcs[i];
        if (fn.address == 0) continue;
        std::string retStr = fn.returnType != NullType ?
            types.formatType(fn.returnType) : "int";
        printf("  %08X  %s %s(", fn.address, retStr.c_str(), fn.name.c_str());
        for (size_t p = 0; p < fn.params.size(); ++p) {
            if (p) printf(", ");
            auto &par = fn.params[p];
            if (par.typeRef != NullType)
                printf("%s", types.formatDecl(par.typeRef, par.name).c_str());
            else
                printf("int %s", par.name.c_str());
        }
        printf(")\n");
    }
}

static int gccCheck(const QString &code) {
    QProcess proc;
    proc.start("gcc", QStringList()
        << "-x" << "c" << "-fsyntax-only" << "-std=c99"
        << "-Werror=implicit-function-declaration"
        << "-");
    if (!proc.waitForStarted(3000)) {
        fprintf(stderr, "Failed to start gcc\n");
        return -1;
    }
    proc.write(code.toUtf8());
    proc.closeWriteChannel();
    if (!proc.waitForFinished(30000)) {
        fprintf(stderr, "gcc timed out\n");
        return -1;
    }

    QByteArray err = proc.readAllStandardError();
    if (!err.isEmpty())
        fprintf(stderr, "%s", err.constData());

    // Count error lines
    int errors = 0;
    for (auto &line : err.split('\n')) {
        if (line.contains(": error:"))
            errors++;
    }
    if (proc.exitCode() == 0) {
        printf("gcc: OK (no errors)\n");
    } else {
        printf("gcc: %d errors\n", errors);
    }
    return errors;
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    if (argc < 2) {
        fprintf(stderr,
            "Usage: decomp <binary> [options]\n"
            "  -l           List source files\n"
            "  -F           List functions\n"
            "  -f <addr>    Decompile function at hex address\n"
            "  -n <name>    Decompile function by name (substring match)\n"
            "  -s <idx>     Decompile source file by index\n"
            "  -a           Decompile all source files\n"
            "  --gcc        Pipe output through gcc to count errors\n"
            "  --ssa        Enable full SSA pass (experimental)\n"
            "  --types      Dump all STABS types as C header\n"
            "  --srcof <addr> Find source file index for function at address\n"
            "  -q           Quiet: suppress decompiled output (use with --gcc)\n"
        );
        return 1;
    }

    const char *binPath = argv[1];
    bool doList = false, doFuncs = false, doAll = false;
    bool doGcc = false, quiet = false, doTypes = false;
    uint32_t srcOfAddr = 0;
    uint32_t funcAddr = 0;
    int srcIdx = -1;
    const char *funcName = nullptr;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "-l") == 0) doList = true;
        else if (strcmp(argv[i], "-F") == 0) doFuncs = true;
        else if (strcmp(argv[i], "-a") == 0) doAll = true;
        else if (strcmp(argv[i], "--gcc") == 0) doGcc = true;
        else if (strcmp(argv[i], "--ssa") == 0) Decompiler::s_useSSA = true;
        else if (strcmp(argv[i], "--flat") == 0) Decompiler::s_flatMode = true;
        else if (strcmp(argv[i], "--types") == 0) doTypes = true;
        else if (strcmp(argv[i], "--srcof") == 0 && i + 1 < argc)
            srcOfAddr = strtoul(argv[++i], nullptr, 16);
        else if (strcmp(argv[i], "-q") == 0) quiet = true;
        else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc)
            funcAddr = strtoul(argv[++i], nullptr, 16);
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
            srcIdx = atoi(argv[++i]);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            funcName = argv[++i];
    }

    MachOFile mf;
    if (!mf.load(binPath)) {
        fprintf(stderr, "Failed to load %s\n", binPath);
        return 1;
    }
    fprintf(stderr, "Loaded %s: %zu bytes, %zu functions, %zu source files\n",
            binPath, mf.size(), mf.stabsFunctions().size(),
            mf.stabsSourceFiles().size());

    if (doList) { listSourceFiles(mf); return 0; }
    if (doFuncs) { listFunctions(mf); return 0; }
    if (doTypes) {
        QString hdr = Decompiler::dumpTypes(mf);
        printf("%s", hdr.toUtf8().constData());
        return 0;
    }
    if (srcOfAddr) {
        auto &sources = mf.stabsSourceFiles();
        for (size_t si = 0; si < sources.size(); ++si) {
            for (size_t fi : sources[si].functionIndices) {
                if (mf.stabsFunctions()[fi].address == srcOfAddr) {
                    printf("%zu\n", si);
                    return 0;
                }
            }
        }
        fprintf(stderr, "Function at 0x%X not found in any source file\n", srcOfAddr);
        return 1;
    }

    QString output;

    if (funcAddr != 0) {
        output = Decompiler::decompile(mf, funcAddr);
    } else if (funcName) {
        auto &funcs = mf.stabsFunctions();
        bool found = false;
        for (auto &fn : funcs) {
            if (fn.address == 0) continue;
            if (fn.name.find(funcName) != std::string::npos) {
                fprintf(stderr, "Decompiling: %s @ 0x%08X\n", fn.name.c_str(), fn.address);
                output += Decompiler::decompile(mf, fn.address);
                output += "\n";
                found = true;
            }
        }
        if (!found) {
            fprintf(stderr, "No function matching '%s'\n", funcName);
            return 1;
        }
    } else if (srcIdx >= 0) {
        output = Decompiler::decompileFile(mf, srcIdx);
    } else if (doAll) {
        auto &sources = mf.stabsSourceFiles();
        int totalErrors = 0;
        for (size_t i = 0; i < sources.size(); ++i) {
            auto &sf = sources[i];
            if (sf.functionIndices.empty()) continue;
            fprintf(stderr, "Decompiling [%zu] %s%s...\n",
                    i, sf.directory.c_str(), sf.filename.c_str());
            QString fileOut = Decompiler::decompileFile(mf, (int)i);
            if (!quiet) {
                printf("// ═══ [%zu] %s%s ═══\n",
                       i, sf.directory.c_str(), sf.filename.c_str());
                printf("%s\n", fileOut.toUtf8().constData());
            }
            if (doGcc) {
                int errs = gccCheck(fileOut);
                if (errs > 0) totalErrors += errs;
            }
        }
        if (doGcc)
            printf("\n=== Total: %d gcc errors across %zu files ===\n",
                   totalErrors, sources.size());
        return 0;
    } else {
        fprintf(stderr, "No action specified. Use -l, -F, -f, -n, -s, or -a\n");
        return 1;
    }

    if (!quiet)
        printf("%s", output.toUtf8().constData());
    if (doGcc)
        gccCheck(output);

    return 0;
}
